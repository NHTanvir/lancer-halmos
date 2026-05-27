//! SMT solver abstraction: subprocess-based z3/yices/cvc5/bitwuzla.
//!
//! Queries are formatted in SMT-LIB2 and piped to the solver binary.
//! Supports timeout, model extraction, and unsat caching.

use std::collections::HashMap;
use std::process::{Command, Stdio};
use std::io::Write;
use std::time::{Duration, Instant};
use anyhow::{anyhow, Result};
use primitive_types::U256;

use crate::symbolic::{Expr, Pred};
use crate::state::Path;

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum SatResult {
    Sat,
    Unsat,
    Unknown,
}

#[derive(Debug, Clone)]
pub struct SolverModel {
    pub assignments: HashMap<String, U256>,
}

impl SolverModel {
    pub fn get(&self, name: &str) -> Option<U256> {
        self.assignments.get(name).copied()
    }
}

#[derive(Debug, Clone)]
pub struct SolverConfig {
    pub backend: SolverBackend,
    pub command: Option<String>,
    pub timeout_branching_ms: u64,
    pub timeout_assertion_ms: u64,
    pub max_memory_mb: u64,
    pub threads: usize,
    pub cache_unsat: bool,
    pub dump_smt_dir: Option<std::path::PathBuf>,
}

impl Default for SolverConfig {
    fn default() -> Self {
        Self {
            backend: SolverBackend::Z3,
            command: None,
            timeout_branching_ms: 1000,
            timeout_assertion_ms: 60_000,
            max_memory_mb: 0,
            threads: 1,
            cache_unsat: false,
            dump_smt_dir: None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum SolverBackend {
    Z3,
    Yices,
    Cvc5,
    Bitwuzla,
    Stp,
}

impl SolverBackend {
    pub fn binary_name(&self) -> &'static str {
        match self {
            SolverBackend::Z3 => "z3",
            SolverBackend::Yices => "yices-smt2",
            SolverBackend::Cvc5 => "cvc5",
            SolverBackend::Bitwuzla => "bitwuzla",
            SolverBackend::Stp => "stp",
        }
    }

    pub fn extra_args(&self) -> Vec<&'static str> {
        match self {
            SolverBackend::Z3 => vec!["-in"],
            SolverBackend::Yices => vec!["--incremental"],
            SolverBackend::Cvc5 => vec!["--lang=smt2", "--produce-models"],
            SolverBackend::Bitwuzla => vec!["--lang=smt2"],
            SolverBackend::Stp => vec!["--SMTLIB2"],
        }
    }
}

pub struct Solver {
    config: SolverConfig,
    /// Unsat cache: hash of constraint set → Unsat
    unsat_cache: std::sync::Mutex<HashMap<u64, ()>>,
    query_counter: std::sync::atomic::AtomicUsize,
}

impl Solver {
    pub fn new(config: SolverConfig) -> Self {
        Self {
            config,
            unsat_cache: std::sync::Mutex::new(HashMap::new()),
            query_counter: std::sync::atomic::AtomicUsize::new(0),
        }
    }

    fn binary(&self) -> String {
        self.config.command.clone()
            .unwrap_or_else(|| self.config.backend.binary_name().to_string())
    }

    /// Check satisfiability of constraints (with variable declarations)
    pub fn check_sat(&self, path: &Path, extra: &[Pred]) -> SatResult {
        let query = self.build_query(path, extra, false);
        self.run_query(&query, self.config.timeout_branching_ms)
            .map(|(sat, _)| sat)
            .unwrap_or(SatResult::Unknown)
    }

    /// Check satisfiability and extract model
    pub fn check_sat_with_model(&self, path: &Path, extra: &[Pred]) -> (SatResult, Option<SolverModel>) {
        let query = self.build_query(path, extra, true);
        match self.run_query(&query, self.config.timeout_assertion_ms) {
            Ok((SatResult::Sat, Some(output))) => {
                let model = parse_model(&output);
                (SatResult::Sat, Some(model))
            }
            Ok((sat, _)) => (sat, None),
            Err(_) => (SatResult::Unknown, None),
        }
    }

    fn build_query(&self, path: &Path, extra: &[Pred], get_model: bool) -> String {
        let mut all_constraints: Vec<Pred> = path.constraints.clone();
        all_constraints.extend(extra.iter().cloned());

        // Collect all free variables
        let mut vars: Vec<String> = Vec::new();
        for c in &all_constraints {
            vars.extend(c.free_vars());
        }
        vars.sort();
        vars.dedup();

        let mut s = String::new();
        s.push_str("(set-logic QF_BV)\n");

        for var in &vars {
            s.push_str(&format!("(declare-fun {} () (_ BitVec 256))\n", var));
        }

        // Keccak as uninterpreted function
        s.push_str("(declare-fun keccak256 ((_ BitVec 256)) (_ BitVec 256))\n");
        // Exp as uninterpreted function
        s.push_str("(declare-fun exp_bv256 ((_ BitVec 256) (_ BitVec 256)) (_ BitVec 256))\n");
        s.push_str("(declare-fun signextend_bv256 ((_ BitVec 256) (_ BitVec 256)) (_ BitVec 256))\n");
        s.push_str("(declare-fun byte_of_bv256 ((_ BitVec 256) (_ BitVec 256)) (_ BitVec 256))\n");

        for c in &all_constraints {
            s.push_str(&format!("(assert {})\n", c.to_smt2()));
        }

        s.push_str("(check-sat)\n");
        if get_model {
            s.push_str("(get-model)\n");
        }

        // Optionally dump to file
        if let Some(dir) = &self.config.dump_smt_dir {
            let n = self.query_counter.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            let path = dir.join(format!("query_{:06}.smt2", n));
            let _ = std::fs::write(&path, &s);
        }

        s
    }

    fn run_query(&self, query: &str, timeout_ms: u64) -> Result<(SatResult, Option<String>)> {
        let binary = self.binary();
        let args = self.config.backend.extra_args();

        let mut cmd = Command::new(&binary);
        cmd.args(&args)
           .stdin(Stdio::piped())
           .stdout(Stdio::piped())
           .stderr(Stdio::null());

        let mut child = cmd.spawn()
            .map_err(|e| anyhow!("Failed to spawn solver '{}': {}. Is it in PATH?", binary, e))?;

        {
            let stdin = child.stdin.as_mut().ok_or_else(|| anyhow!("No stdin"))?;
            stdin.write_all(query.as_bytes())?;
        }

        let start = Instant::now();
        let output = child.wait_with_output()?;

        if start.elapsed() > Duration::from_millis(timeout_ms) {
            return Ok((SatResult::Unknown, None));
        }

        let stdout = String::from_utf8_lossy(&output.stdout).to_string();
        let first_line = stdout.lines().next().unwrap_or("").trim();

        let sat = match first_line {
            "sat" => SatResult::Sat,
            "unsat" => SatResult::Unsat,
            _ => SatResult::Unknown,
        };

        if sat == SatResult::Sat {
            Ok((sat, Some(stdout)))
        } else {
            Ok((sat, None))
        }
    }
}

/// Parse a z3 model output to extract variable assignments
fn parse_model(output: &str) -> SolverModel {
    let mut assignments = HashMap::new();
    // z3 model format: (define-fun varname () (_ BitVec 256) #x...)
    for line in output.lines() {
        let line = line.trim();
        if line.starts_with("(define-fun") {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 6 {
                let name = parts[1].to_string();
                let val_str = parts[parts.len()-1].trim_end_matches(')');
                if let Some(val) = parse_bv_literal(val_str) {
                    assignments.insert(name, val);
                }
            }
        }
    }
    SolverModel { assignments }
}

/// Parse #x{hex} or #b{bin} or (_ bv{dec} {width}) bitvector literals
fn parse_bv_literal(s: &str) -> Option<U256> {
    if let Some(hex) = s.strip_prefix("#x") {
        let padded = format!("{:0>64}", hex);
        let bytes = hex::decode(&padded).ok()?;
        Some(U256::from_big_endian(&bytes))
    } else if let Some(bin) = s.strip_prefix("#b") {
        let val = U256::from_str_radix(bin, 2).ok()?;
        Some(val)
    } else if s.starts_with("(_ bv") {
        // (_ bv{decimal} {width})
        let inner = s.trim_start_matches("(_ bv").trim_end_matches(')');
        let mut parts = inner.split_whitespace();
        let dec = parts.next()?;
        Some(u256_from_dec_str(dec).ok()?)
    } else {
        None
    }
}

fn u256_from_dec_str(s: &str) -> Result<U256, ()> {
    use num_bigint::BigUint;
    let n: BigUint = s.parse().map_err(|_| ())?;
    let bytes = n.to_bytes_be();
    let mut padded = vec![0u8; 32];
    let offset = 32usize.saturating_sub(bytes.len());
    let copy_len = bytes.len().min(32);
    if !bytes.is_empty() {
        padded[offset..offset+copy_len].copy_from_slice(&bytes[bytes.len()-copy_len..]);
    }
    Ok(U256::from_big_endian(&padded))
}
