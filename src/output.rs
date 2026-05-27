//! PASS/FAIL output, JSON output, and statistics.

use std::collections::HashMap;
use std::time::Duration;
use serde::{Deserialize, Serialize};
use primitive_types::U256;

use crate::solver::SolverModel;
use crate::state::Frame;
use crate::exceptions::HaltReason;

#[derive(Debug, Clone, PartialEq)]
pub enum TestStatus {
    Pass,
    Fail,
    Error(String),
}

#[derive(Debug, Clone)]
pub struct TestResult {
    pub contract: String,
    pub function: String,
    pub status: TestStatus,
    pub paths_explored: usize,
    pub paths_pass: usize,
    pub paths_fail: usize,
    pub elapsed: Duration,
    pub counterexample: Option<Counterexample>,
    pub message: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Counterexample {
    pub args: HashMap<String, String>,
    pub revert_reason: Option<String>,
    pub trace: String,
}

impl TestResult {
    pub fn pass(contract: &str, func: &str, paths: usize, elapsed: Duration) -> Self {
        Self {
            contract: contract.to_string(),
            function: func.to_string(),
            status: TestStatus::Pass,
            paths_explored: paths,
            paths_pass: paths,
            paths_fail: 0,
            elapsed,
            counterexample: None,
            message: None,
        }
    }

    pub fn fail(contract: &str, func: &str, paths: usize, elapsed: Duration, cex: Counterexample, msg: String) -> Self {
        Self {
            contract: contract.to_string(),
            function: func.to_string(),
            status: TestStatus::Fail,
            paths_explored: paths,
            paths_pass: 0,
            paths_fail: 1,
            elapsed,
            counterexample: Some(cex),
            message: Some(msg),
        }
    }
}

pub struct ResultPrinter {
    pub verbose: bool,
    pub statistics: bool,
    pub json_output: Option<std::path::PathBuf>,
    pub no_color: bool,
}

impl ResultPrinter {
    pub fn new(verbose: bool, statistics: bool, json_output: Option<std::path::PathBuf>) -> Self {
        Self { verbose, statistics, json_output, no_color: false }
    }

    pub fn print_result(&self, result: &TestResult) {
        let status_str = match &result.status {
            TestStatus::Pass => "[PASS]",
            TestStatus::Fail => "[FAIL]",
            TestStatus::Error(e) => "[ERROR]",
        };

        let func_display = format!("{}::{}", result.contract, result.function);
        println!("{} {} (paths: {}, time: {:.2?})",
            status_str,
            func_display,
            result.paths_explored,
            result.elapsed,
        );

        if let TestStatus::Fail = &result.status {
            if let Some(cex) = &result.counterexample {
                println!("  Counterexample:");
                for (k, v) in &cex.args {
                    println!("    {} = {}", k, v);
                }
                if let Some(reason) = &cex.revert_reason {
                    println!("  Revert: {}", reason);
                }
                if self.verbose && !cex.trace.is_empty() {
                    println!("  Trace:");
                    for line in cex.trace.lines() {
                        println!("    {}", line);
                    }
                }
            }
            if let Some(msg) = &result.message {
                println!("  {}", msg);
            }
        }

        if self.statistics {
            println!("  Stats: {} pass, {} fail", result.paths_pass, result.paths_fail);
        }
    }

    pub fn print_summary(&self, results: &[TestResult]) {
        let pass = results.iter().filter(|r| r.status == TestStatus::Pass).count();
        let fail = results.iter().filter(|r| matches!(r.status, TestStatus::Fail)).count();
        let err = results.iter().filter(|r| matches!(r.status, TestStatus::Error(_))).count();
        let total_time: Duration = results.iter().map(|r| r.elapsed).sum();

        println!("\n── Summary ────────────────────────────");
        println!("  Tests:  {} passed, {} failed, {} errors", pass, fail, err);
        println!("  Time:   {:.2?}", total_time);
        if fail > 0 || err > 0 {
            println!("  Result: FAILED");
        } else {
            println!("  Result: OK");
        }
    }

    pub fn write_json(&self, results: &[TestResult]) {
        let Some(path) = &self.json_output else { return; };
        let json_results: Vec<JsonTestResult> = results.iter().map(|r| {
            JsonTestResult {
                contract: r.contract.clone(),
                function: r.function.clone(),
                status: match &r.status {
                    TestStatus::Pass => "pass",
                    TestStatus::Fail => "fail",
                    TestStatus::Error(_) => "error",
                }.to_string(),
                paths: r.paths_explored,
                elapsed_ms: r.elapsed.as_millis() as u64,
                counterexample: r.counterexample.clone(),
                message: r.message.clone(),
            }
        }).collect();

        let s = serde_json::to_string_pretty(&json_results).unwrap_or_default();
        if let Err(e) = std::fs::write(path, s) {
            tracing::error!("Failed to write JSON output to {:?}: {}", path, e);
        }
    }
}

#[derive(Serialize, Deserialize)]
struct JsonTestResult {
    contract: String,
    function: String,
    status: String,
    paths: usize,
    elapsed_ms: u64,
    counterexample: Option<Counterexample>,
    message: Option<String>,
}

/// Analyze frames from SEVM to produce a TestResult
pub fn analyze_frames(
    contract: &str,
    func_name: &str,
    frames: &[Frame],
    solver: &crate::solver::Solver,
    elapsed: Duration,
    verbose: bool,
) -> TestResult {
    let total = frames.len();
    let mut fail_frame: Option<(&Frame, String)> = None;
    let mut pass_count = 0;

    for frame in frames {
        if let Some(res) = &frame.result {
            let is_fail = match &res.halt {
                HaltReason::Revert(data) => {
                    // Check for assertion failure pattern
                    is_assertion_failure(data)
                }
                _ => false,
            };

            if is_fail {
                let reason = crate::exceptions::decode_revert(
                    match &res.halt { HaltReason::Revert(d) => d, _ => &[] }
                );
                fail_frame = Some((frame, reason));
                break;
            } else {
                pass_count += 1;
            }
        }
    }

    if let Some((frame, reason)) = fail_frame {
        // Try to get a counterexample from the solver
        let (sat, model) = solver.check_sat_with_model(&frame.path, &[]);
        let cex = if sat == crate::solver::SatResult::Sat {
            let model = model.unwrap_or(crate::solver::SolverModel { assignments: Default::default() });
            let args: HashMap<String, String> = model.assignments.iter()
                .map(|(k, v)| (k.clone(), format!("{}", v)))
                .collect();
            let trace = crate::traces::format_trace(frame);
            Counterexample {
                args,
                revert_reason: Some(reason.clone()),
                trace,
            }
        } else {
            Counterexample {
                args: HashMap::new(),
                revert_reason: Some(reason.clone()),
                trace: crate::traces::format_trace(frame),
            }
        };

        TestResult::fail(contract, func_name, total, elapsed, cex, reason)
    } else {
        TestResult::pass(contract, func_name, total, elapsed)
    }
}

/// Check if revert data indicates an assertion failure
fn is_assertion_failure(data: &[u8]) -> bool {
    if data.is_empty() { return false; }
    // Panic(0x01) = assertion failure
    if data.len() >= 4 && data[..4] == crate::exceptions::PANIC_SELECTOR {
        if data.len() >= 36 {
            let code = U256::from_big_endian(&data[4..36]);
            return code == U256::one(); // 0x01 = assertionFailed
        }
    }
    // Empty revert from require/assert
    data.is_empty() || data == b"\x00\x00\x00\x00"
}

/// Write an lcov coverage file (simplified)
pub fn write_coverage(
    frames: &[Frame],
    source_dir: &std::path::Path,
    output_path: &std::path::Path,
) -> anyhow::Result<()> {
    // Collect all visited PCs across all frames
    let mut coverage: HashMap<usize, usize> = HashMap::new();
    for frame in frames {
        coverage.entry(frame.evm.pc).and_modify(|c| *c += 1).or_insert(1);
    }

    let mut lcov = String::new();
    lcov.push_str("TN:\n");
    lcov.push_str(&format!("SF:{}\n", source_dir.display()));
    for (pc, count) in &coverage {
        lcov.push_str(&format!("DA:{},{}\n", pc, count));
    }
    lcov.push_str("end_of_record\n");

    std::fs::write(output_path, lcov)?;
    Ok(())
}
