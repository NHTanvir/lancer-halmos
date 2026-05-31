# CLAUDE.md

Guidance for Claude Code (and humans) working in this repository.

## What this is

`lancer-halmos` — A Rust clone of the `halmos` symbolic EVM testing tool, built as part of the Lancer ecosystem — a complete 2026 AI-era bug bounty toolkit. It performs symbolic execution of EVM smart contracts to automatically find vulnerabilities and verify invariants. The project is currently in active development (scaffold stage), with full implementation tracked in the local `plan.md`.

## Architecture

- `src/main.rs` — Binary entry point; CLI argument parsing and program initialization.
- `src/abi.rs` — ABI encoding/decoding for contract interaction.
- `src/artifacts.rs` — Loading and parsing compiled contract artifacts (JSON output from solc/foundry).
- `src/calldata.rs` — Symbolic calldata generation for fuzzing and symbolic execution.
- `src/cheatcodes.rs` — Support for Foundry-style cheatcodes (vm.assume, vm.prank, etc.).
- `src/config.rs` — Configuration loading and management (TOML/CLI flags).
- `src/contract.rs` — Contract representation and metadata.
- `src/exceptions.rs` — Custom error/exception types for EVM execution.
- `src/invariant.rs` — Invariant checking and property verification logic.
- `src/memory.rs` — Symbolic EVM memory model.
- `src/opcodes.rs` — EVM opcode definitions and dispatch.
- `src/output.rs` — Result formatting and output serialization.
- `src/sevm.rs` — Symbolic EVM interpreter (core execution engine).
- `src/solver.rs` — SMT/constraint solver integration for path feasibility.
- `src/state.rs` — EVM execution state (stack, memory, storage snapshots).
- `src/storage.rs` — Symbolic storage model for contract state.
- `src/symbolic.rs` — Symbolic value representation and expression trees.
- `src/traces.rs` — Execution trace recording and reporting.
- `src/types.rs` — Shared primitive types used across modules.

## Conventions

- Error propagation uses `anyhow::Result`; no `unwrap`/`expect` on fallible I/O.
- Library code lives in `src/`; binary entry point in `src/main.rs`.
- Async runtime is Tokio (`tokio = { features = ["full"] }`); use `#[tokio::main]` for async entry points.
- CLI surface is defined with `clap` derive macros; keep argument structs in `src/main.rs` or a dedicated `src/cli.rs` if it grows.
- Parallelism uses `rayon` for CPU-bound symbolic execution tasks; keep Tokio for I/O-bound work.
- Serialization uses `serde` + `serde_json`; all public data types that cross API boundaries should derive `Serialize`/`Deserialize`.
- Structured logging uses the `tracing` crate; use `tracing::instrument` on hot paths for diagnostics.

## Build / test / run

```
build.bat                   # Windows → build\lancer-halmos.exe
build-windows.bat           # Windows packaged dist → dist\lancer-halmos-windows-x86_64\bin\lancer-halmos.exe
./build-linux.sh            # Linux/macOS
cargo build --release       # standard release build
cargo test                  # unit + integration tests
```

## Repo notes

- `plan.md` is local-only and must NOT be committed. It is gitignored; if ever tracked, run `git rm --cached plan.md`.
- `.claude/` and `target/`/`build/`/`dist/` are local-only and gitignored.
