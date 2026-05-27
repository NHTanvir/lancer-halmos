//! CLI configuration: all flags mirroring halmos CLI.

use clap::Parser;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Parser, Debug, Clone)]
#[command(
    name = "lancer-halmos",
    version,
    about = "Symbolic execution / model checker for EVM smart contracts (Rust clone of halmos)"
)]
pub struct Cli {
    // ── Test discovery ─────────────────────────────────────────────────────────
    /// Project root directory
    #[arg(long, default_value = ".")]
    pub root: PathBuf,

    /// Path to halmos.toml config file
    #[arg(long)]
    pub config: Option<PathBuf>,

    /// Only run a specific contract
    #[arg(long)]
    pub contract: Option<String>,

    /// Regex to match contract names
    #[arg(long, short = 'c')]
    pub match_contract: Option<String>,

    /// Function name prefix / regex to match test functions
    #[arg(long, default_value = "(check|invariant)_")]
    pub function: String,

    /// Regex to match test function names
    #[arg(long, short = 't')]
    pub match_test: Option<String>,

    /// Additional panic error codes to treat as failures
    #[arg(long, default_value = "0x01")]
    pub panic_error_codes: Vec<String>,

    /// Max call depth for invariant sequences
    #[arg(long, default_value = "2")]
    pub invariant_depth: usize,

    // ── Bounds ─────────────────────────────────────────────────────────────────
    /// Loop unrolling bound
    #[arg(long, default_value = "2")]
    pub r#loop: usize,

    /// Max concurrent paths (0 = unlimited)
    #[arg(long, default_value = "0")]
    pub width: usize,

    /// Max steps per path (0 = unlimited)
    #[arg(long, default_value = "0")]
    pub depth: usize,

    /// Default array lengths to try
    #[arg(long, value_delimiter = ',', default_value = "0,1,2")]
    pub default_array_lengths: Vec<usize>,

    /// Default bytes lengths to try
    #[arg(long, value_delimiter = ',', default_value = "0,65,1024")]
    pub default_bytes_lengths: Vec<usize>,

    // ── Storage/build ──────────────────────────────────────────────────────────
    /// Storage layout model
    #[arg(long, default_value = "solidity")]
    pub storage_layout: StorageLayout,

    /// Forge build output directory
    #[arg(long, default_value = "out")]
    pub forge_build_out: String,

    /// Enable FFI cheatcode
    #[arg(long)]
    pub ffi: bool,

    // ── Solver ─────────────────────────────────────────────────────────────────
    /// SMT solver backend
    #[arg(long, default_value = "z3")]
    pub solver: SolverName,

    /// Override solver binary command
    #[arg(long)]
    pub solver_command: Option<String>,

    /// Solver timeout for branching queries (ms)
    #[arg(long, default_value = "1000")]
    pub solver_timeout_branching: u64,

    /// Solver timeout for assertion queries (ms)
    #[arg(long, default_value = "60000")]
    pub solver_timeout_assertion: u64,

    /// Max memory for solver (0 = unlimited)
    #[arg(long, default_value = "0")]
    pub solver_max_memory: u64,

    /// Number of solver threads
    #[arg(long)]
    pub solver_threads: Option<usize>,

    /// Exponentiation bound for SMT (precompute base^exp for exp < N)
    #[arg(long, default_value = "2")]
    pub smt_exp_by_const: usize,

    /// Cache unsat results across paths
    #[arg(long)]
    pub cache_solver: bool,

    // ── Output / debug ─────────────────────────────────────────────────────────
    /// Verbose output
    #[arg(long, short = 'v')]
    pub verbose: bool,

    /// Print statistics
    #[arg(long, short = 's')]
    pub statistics: bool,

    /// Debug mode
    #[arg(long)]
    pub debug: bool,

    /// JSON output file path
    #[arg(long)]
    pub json_output: Option<PathBuf>,

    /// Minimal JSON output
    #[arg(long)]
    pub minimal_json_output: bool,

    /// Print successful states
    #[arg(long)]
    pub print_success_states: bool,

    /// Print failed states
    #[arg(long)]
    pub print_failed_states: bool,

    /// Print all states
    #[arg(long)]
    pub print_states: bool,

    /// Stop after first failure
    #[arg(long)]
    pub early_exit: bool,

    /// Directory to dump SMT queries
    #[arg(long)]
    pub dump_smt_queries: Option<PathBuf>,

    /// Coverage output file (lcov format)
    #[arg(long)]
    pub coverage_output: Option<PathBuf>,

    /// Suppress live progress
    #[arg(long)]
    pub no_status: bool,

    // ── Experimental ──────────────────────────────────────────────────────────
    /// Enable symbolic jump resolution
    #[arg(long)]
    pub symbolic_jump: bool,
}

#[derive(Debug, Clone, clap::ValueEnum, Serialize, Deserialize, PartialEq)]
pub enum StorageLayout {
    Solidity,
    Generic,
}

#[derive(Debug, Clone, clap::ValueEnum, Serialize, Deserialize, PartialEq)]
pub enum SolverName {
    Z3,
    Yices,
    Cvc5,
    Bitwuzla,
    Stp,
}

impl SolverName {
    pub fn to_backend(&self) -> crate::solver::SolverBackend {
        match self {
            SolverName::Z3 => crate::solver::SolverBackend::Z3,
            SolverName::Yices => crate::solver::SolverBackend::Yices,
            SolverName::Cvc5 => crate::solver::SolverBackend::Cvc5,
            SolverName::Bitwuzla => crate::solver::SolverBackend::Bitwuzla,
            SolverName::Stp => crate::solver::SolverBackend::Stp,
        }
    }
}

/// Runtime configuration (derived from Cli + halmos.toml)
#[derive(Debug, Clone)]
pub struct Config {
    pub root: std::path::PathBuf,
    pub contract_pattern: Option<String>,
    pub function_pattern: String,
    pub loop_bound: usize,
    pub width: usize,
    pub depth: usize,
    pub invariant_depth: usize,
    pub smt_exp_by_const: usize,
    pub solver: crate::solver::SolverConfig,
    pub verbose: bool,
    pub statistics: bool,
    pub early_exit: bool,
    pub ffi: bool,
    pub json_output: Option<std::path::PathBuf>,
    pub coverage_output: Option<std::path::PathBuf>,
    pub forge_build_out: String,
}

impl Config {
    pub fn from_cli(cli: &Cli) -> Self {
        let solver = crate::solver::SolverConfig {
            backend: cli.solver.to_backend(),
            command: cli.solver_command.clone(),
            timeout_branching_ms: cli.solver_timeout_branching,
            timeout_assertion_ms: cli.solver_timeout_assertion,
            max_memory_mb: cli.solver_max_memory,
            threads: cli.solver_threads.unwrap_or(1),
            cache_unsat: cli.cache_solver,
            dump_smt_dir: cli.dump_smt_queries.clone(),
        };

        let pattern = if let Some(mc) = &cli.match_contract {
            Some(mc.clone())
        } else {
            cli.contract.clone()
        };

        Self {
            root: cli.root.clone(),
            contract_pattern: pattern,
            function_pattern: cli.function.clone(),
            loop_bound: cli.r#loop,
            width: cli.width,
            depth: cli.depth,
            invariant_depth: cli.invariant_depth,
            smt_exp_by_const: cli.smt_exp_by_const,
            solver,
            verbose: cli.verbose,
            statistics: cli.statistics,
            early_exit: cli.early_exit,
            ffi: cli.ffi,
            json_output: cli.json_output.clone(),
            coverage_output: cli.coverage_output.clone(),
            forge_build_out: cli.forge_build_out.clone(),
        }
    }
}
