//! lancer-halmos — Rust clone of halmos
//! Bounded symbolic execution / model checker for EVM smart contracts.

mod abi;
mod artifacts;
mod calldata;
mod cheatcodes;
mod config;
mod contract;
mod exceptions;
mod invariant;
mod memory;
mod opcodes;
mod output;
mod sevm;
mod solver;
mod state;
mod storage;
mod symbolic;
mod traces;
mod types;

use std::time::Instant;
use anyhow::Result;
use clap::Parser;
use tracing_subscriber::EnvFilter;

use crate::artifacts::load_foundry_artifacts;
use crate::calldata::build_symbolic_message;
use crate::config::{Cli, Config};
use crate::contract::{discover_tests, find_setup_function, summarize};
use crate::exceptions::HaltReason;
use crate::output::{analyze_frames, ResultPrinter, TestResult};
use crate::sevm::SEVM;
use crate::solver::{Solver, SolverConfig};
use crate::state::{BlockCtx, Frame, Message};
use crate::storage::WorldState;
use crate::symbolic::Expr;

fn main() -> Result<()> {
    let cli = Cli::parse();

    // Initialise logging
    let filter = if cli.debug {
        "lancer_halmos=debug,warn"
    } else if cli.verbose {
        "lancer_halmos=info,warn"
    } else {
        "warn"
    };
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::new(filter))
        .with_target(false)
        .init();

    let config = Config::from_cli(&cli);

    println!("lancer-halmos v{}", env!("CARGO_PKG_VERSION"));
    println!("Root: {}", config.root.display());
    println!("Solver: {:?} (timeout: {}ms branch, {}ms assert)",
        cli.solver, config.solver.timeout_branching_ms, config.solver.timeout_assertion_ms);
    println!("Bounds: loop={}, depth={}, width={}",
        config.loop_bound, config.depth, config.width);
    println!();

    // Load Foundry artifacts
    let artifacts = match load_foundry_artifacts(&config.root) {
        Ok(a) => a,
        Err(e) => {
            eprintln!("Error loading artifacts: {}", e);
            eprintln!("Run `forge build` in your project root first.");
            std::process::exit(1);
        }
    };

    if artifacts.is_empty() {
        eprintln!("No contracts found in out/. Run `forge build` first.");
        std::process::exit(1);
    }

    tracing::info!("Loaded {} contract artifacts", artifacts.len());

    // Find test contracts
    let test_contracts = artifacts::find_test_contracts(&artifacts, &config.contract_pattern);
    if test_contracts.is_empty() {
        eprintln!("No test contracts found matching pattern.");
        eprintln!("Contracts found: {:?}", artifacts.keys().collect::<Vec<_>>());
        std::process::exit(1);
    }

    // Build solver
    let solver = Solver::new(config.solver.clone());

    // Build result printer
    let printer = ResultPrinter::new(
        config.verbose,
        config.statistics,
        config.json_output.clone(),
    );

    let mut all_results: Vec<TestResult> = Vec::new();
    let mut any_failure = false;

    // Run tests for each contract
    for contract in &test_contracts {
        let tests = discover_tests(contract, &config.function_pattern);
        if tests.is_empty() { continue; }

        println!("Contract: {}", contract.name);
        println!("{}", summarize(&tests));

        // Run setUp() once to get initial world state
        let (initial_world, initial_block) = run_setup(contract, &solver, &config);

        for test in &tests {
            if test.is_invariant {
                // Invariant testing mode
                let results = invariant::run_invariant_tests(
                    contract,
                    &[],
                    initial_world.clone(),
                    initial_block.clone(),
                    &config,
                    &solver,
                );
                for inv_result in results {
                    let status = if inv_result.passed {
                        output::TestStatus::Pass
                    } else {
                        output::TestStatus::Fail
                    };
                    let tr = TestResult {
                        contract: contract.name.clone(),
                        function: inv_result.invariant_name.clone(),
                        status: status.clone(),
                        paths_explored: 1,
                        paths_pass: if inv_result.passed { 1 } else { 0 },
                        paths_fail: if !inv_result.passed { 1 } else { 0 },
                        elapsed: std::time::Duration::from_secs(0),
                        counterexample: None,
                        message: Some(inv_result.message),
                    };
                    if matches!(status, output::TestStatus::Fail) {
                        any_failure = true;
                    }
                    printer.print_result(&tr);
                    all_results.push(tr);
                }
            } else {
                // check_ function
                let start = Instant::now();
                let msg = build_symbolic_message(&test.func, test_contract_addr(contract), [0xaa; 20]);
                let frame = Frame::new(
                    contract.deployed_bytecode.clone(),
                    msg,
                    initial_world.clone(),
                    initial_block.clone(),
                );

                let sevm = SEVM::new(&config, &solver);
                let frames = sevm.run(frame);
                let elapsed = start.elapsed();

                let result = analyze_frames(
                    &contract.name,
                    &test.function_name,
                    &frames,
                    &solver,
                    elapsed,
                    config.verbose,
                );

                if matches!(result.status, output::TestStatus::Fail) {
                    any_failure = true;
                }
                printer.print_result(&result);
                all_results.push(result);

                if config.early_exit && any_failure { break; }
            }
        }

        if config.early_exit && any_failure { break; }
    }

    printer.print_summary(&all_results);
    printer.write_json(&all_results);

    // Write coverage if requested
    if let Some(cov_path) = &config.coverage_output {
        let all_frames: Vec<_> = vec![]; // Would collect from run results
        let _ = output::write_coverage(&all_frames, &config.root, cov_path);
    }

    if any_failure {
        std::process::exit(1);
    }
    Ok(())
}

/// Run setUp() to get the initial world state for a test contract
fn run_setup(
    contract: &artifacts::Contract,
    solver: &Solver,
    config: &Config,
) -> (WorldState, BlockCtx) {
    let mut world = WorldState::new();
    let block = BlockCtx::default();

    // Deploy the contract at a fixed address
    let addr = test_contract_addr(contract);
    world.deploy_code(addr, contract.deployed_bytecode.clone());

    // Find and run setUp()
    if let Some(setup_fn) = find_setup_function(contract) {
        let selector = setup_fn.selector();
        let calldata = selector.to_vec();
        let msg = Message {
            caller: [0xaa; 20],
            callee: addr,
            origin: [0xaa; 20],
            callvalue: Expr::Concrete(primitive_types::U256::zero()),
            calldata,
            calldata_sym: vec![],
            gas: 30_000_000,
            is_static: false,
            depth: 0,
        };

        let frame = Frame::new(contract.deployed_bytecode.clone(), msg, world.clone(), block.clone());
        let sevm = SEVM::new(config, solver);
        let frames = sevm.run(frame);

        // Take the first successful setup frame
        for f in frames {
            if let Some(res) = &f.result {
                if res.success {
                    tracing::info!("setUp() succeeded");
                    return (f.world, block);
                }
            }
        }
        tracing::warn!("setUp() failed or produced no results");
    }

    (world, block)
}

/// Assign a deterministic address to a test contract
fn test_contract_addr(contract: &artifacts::Contract) -> [u8; 20] {
    let hash = types::keccak256(contract.name.as_bytes());
    let mut addr = [0u8; 20];
    addr.copy_from_slice(&hash[12..32]);
    addr
}
