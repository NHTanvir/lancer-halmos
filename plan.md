# RESEARCH DOSSIER: Halmos

> Part of the Lancer ecosystem. A Rust (or Python) clone of a16z's Halmos — bounded symbolic execution / model checker for EVM. Build with Claude Code.
> Upstream: github.com/a16z/halmos (Python, AGPL-3.0, v0.3+ Q1 2025 added invariant testing).

## Feature Parity Mandate

**`lancer-halmos` MUST ship with 100% feature parity to the upstream `halmos` tool — every flag, every subcommand, every output format, every probe / detector / module / payload / mode — plus a native Rust GUI on top.** This is not a "subset clone" — this is a full reimplementation in Rust with a GUI wrapper.

### Parity contract

- **Every CLI flag** documented in upstream `halmos --help` (and the long-form man page / docs) must work in `lancer-halmos --cli`.
- **Every output format** the upstream tool emits (text, JSON, XML, CSV, SARIF, custom formats) must round-trip through `lancer-halmos` byte-equivalent where the format allows.
- **Every probe / detector / module / category / payload class / built-in script** must be ported. None silently dropped.
- **Every supported target type / input format / protocol / file format / language** must work.
- **Every configuration option** (config files, env vars, registry / settings entries) must be honoured.
- **Companion binaries / sub-tools** in the upstream suite (if any) must each get their own binary in this workspace.

### GUI on top

Every feature reachable via CLI is also reachable from the GUI (see `## GUI (Lancer-standard pattern)` below). The GUI is not a subset — it is an alternate frontend over the same `core` library that the CLI uses. The `core` crate is GUI-agnostic.

### Verification

- The `## Granular feature catalog` section below enumerates everything that must be supported.
- Reference: `tests/upstream_parity/` will pin upstream flag combinations + canned outputs as parity tests. CI fails if any flag is unsupported or output diverges.
- A `lancer-halmos --self-test` flag runs the full parity matrix against a bundled reference target and prints pass/fail per upstream feature group.

### What is allowed to diverge

- **Performance** — Rust-native, async-first; we are allowed to be faster.
- **Memory footprint** — we are allowed to be smaller.
- **GUI** — entirely new (no upstream GUI to copy except where the upstream ships its own GUI like Zenmap / Wireshark UI / Ghidra GUI / jadx-gui — in which case our GUI must cover every panel the upstream GUI has, plus the Lancer-standard layout from `## GUI` below).
- **AI augmentation** — net-new (see `## AI augmentation ideas`).

### What is NOT allowed to diverge

- Any flag silently dropped, renamed, or behavior-changed compared to upstream.
- Any output format / record schema diverging in field names, types, or semantics.
- Any built-in script / detector / module not ported (mark explicitly with `[N/A — see note]` if genuinely impossible in Rust, e.g. NSE Lua scripts requiring features not in `mlua`).

## What it actually does

Halmos (a16z, AGPL-3.0) is a symbolic execution / bounded model checker for EVM smart contracts. It reuses your Foundry tests — any function prefixed `check_` (stateless) or `invariant_` (stateful, since v0.3) is symbolically explored. Halmos enumerates execution paths, collects path constraints in Z3/Yices, and tries to find counterexamples that violate assertions. The output is exact: either `[PASS]` (verified up to the bounded loop/depth/path width) or `[FAIL]` with a concrete counterexample. Differs from fuzzing: covers infinite input space deductively rather than sampling. Differs from KEVM/Kontrol: lighter, Python-based, faster startup, Foundry-native. Differs from hevm: Python (vs Haskell), more aggressive bounding by default.

## Internal architecture

**Source layout** (`src/halmos/`):

| File | Purpose |
|---|---|
| `__init__.py`, `__main__.py` | Package + CLI entry |
| `sevm.py` | Symbolic EVM interpreter, path exploration |
| `solve.py`, `solvers.py` | SMT solver abstraction (z3, yices, cvc5, bitwuzla, stp); query batching, caching |
| `cheatcodes.py` | hevm-cheats + halmos svm-cheats (`createUint256`, etc.) |
| `calldata.py` | ABI calldata symbolic encoder/decoder, used by `createCalldata` |
| `mapper.py` | bytecode → source mapping (uses solc PC→AST map) |
| `processes.py` | multiprocessing for parallel path/solver work |
| `traces.py` | per-path execution trace builder |
| `bytevec.py` | symbolic byte vector (memory/calldata model) |
| `bitvec.py` | thin wrapper around z3 BitVec |
| `build.py` | foundry build artifact loader |
| `config.py` | CLI flags → Config dataclass |
| `console.py`, `ui.py`, `logs.py` | output |
| `constants.py` | EVM constants, opcodes, gas table |
| `contract.py` | per-contract test discovery |
| `env.py` | `envXxx` cheatcode backing |
| `exceptions.py` | path-termination signals (`Revert`, `StackUnderflow`, etc.) |
| `flamegraphs.py` | flamegraph rendering for `--flamegraph` |
| `hashes.py` | symbolic keccak with consistency check |
| `assertions.py` | assertion failure semantics |
| `utils.py` | small helpers |

**SEVM (symbolic EVM)** — `sevm.py`:

- `Path` class — wraps a Z3 solver instance; tracks deferred constraints (pushed lazily when path activates) and variable→condition relationships.
- `State` dataclass — stack (list of Z3 BitVec256 or boolean wrappers), `ByteVec` memory, current PC, gas, return data.
- `Message` dataclass — call frame: target, caller, origin, value, calldata.
- `CallContext` — wraps a call: message, output, depth, traces, sub-calls list (recursive trace).
- `CallOutput` — return data, deleted accounts, exception (if any).
- `SEVM` class — opcode dispatch. Worklist = stack of `(Path, State, CallContext)` triples; DFS exploration.

**Path forking at JUMPI:** when condition is symbolic and both branches are SAT under current constraints:
1. Push current solver scope.
2. Create shallow copy of `Path` (constraints conjoined later).
3. Push new `(Path_taken, State_taken, ctx)` and `(Path_not_taken, ...)` to worklist.
4. Lazy constraint addition — defers `solver.add` until the path is activated, saving solver memory.

**CALL / STATICCALL / DELEGATECALL:**
- Concrete target with concrete code: recursive `SEVM.exec` on a child `Message`/`CallContext`, with new `State`.
- Symbolic target (only with `--symbolic-jump`): currently errors out unless `--call-resolution` strategy is on.
- DELEGATECALL preserves caller, value, storage of current contract; CALLCODE same but with value transfer.
- Returndata copied to memory via `bytevec.copy_returndata_to_memory()`, handles partial overwrite.
- For external calls to unknown contracts (e.g., `createCalldata`), Halmos either invokes a stub returning symbolic bytes, or — with `--snapshot-state` — assumes any state change in the unknown contract.

**Storage model.** Two layouts:
- `solidity` (default) — slot indexing follows Solidity's `keccak(key . slot)` for mappings; Halmos uses `--storage-layout solidity` + the storageLayout artifact for typed access.
- `generic` — flat slot mapping; treats storage as `Array<256, 256>` in Z3.

Both modeled as Z3 Arrays. Symbolic SLOAD/SSTORE goes through Array ops. The hard part is keccak: Halmos models `keccak256(x)` as an uninterpreted function with an injectivity axiom + caching of equal symbolic preimages.

**Invariant testing** (v0.3+):
- Discovers `invariant_*` functions in the test contract.
- Discovers target contracts (auto: anything deployed in `setUp()` or via the `targetContract(...)` cheat).
- Discovers target functions on those targets.
- Generates sequences of length `--invariant-depth` (default 2) by symbolically calling any target function with symbolic args.
- After each generated state, asserts every `invariant_*`.
- Counterexamples are concrete call sequences.

## Granular feature list

**CLI flags** (from `config.py`):

*Test discovery:*
- `--root` — project root
- `--config` — `halmos.toml` path
- `--contract <name>` — single contract
- `--match-contract / -mc <regex>`
- `--function <prefix>` (default `(check|invariant)_`)
- `--match-test / -mt <regex>`
- `--panic-error-codes 0x01` — extra failure codes
- `--invariant-depth 2`

*Bounds:*
- `--loop 2` — loop unroll bound
- `--width 0` — concurrent path cap
- `--depth 0` — max steps per path
- `--array-lengths` — explicit sizes
- `--default-array-lengths 0,1,2`
- `--default-bytes-lengths 0,65,1024`

*Storage/build:*
- `--storage-layout {solidity, generic}`
- `--forge-build-out out`
- `--ffi`

*Solver:*
- `--solver yices|z3|cvc5|bitwuzla|stp`
- `--solver-command` — override
- `--solver-timeout-branching 1ms`
- `--solver-timeout-assertion 60s`
- `--solver-max-memory 0`
- `--solver-threads <cpu_count>`
- `--smt-exp-by-const 2`
- `--cache-solver` — unsat caching

*Output/debug:*
- `-v / --verbose`
- `-st / --statistics`
- `--debug`, `--debug-config`
- `--json-output FILE`, `--minimal-json-output`
- `--print-{steps,mem,states,success-states,failed-states,blocked-states,setup-states,full-model}`
- `--early-exit`
- `--dump-smt-queries [DIR]`
- `--dump-smt-directory <DIR>` — custom dir for SMT dumps (v0.3+)
- `--trace-events all|...`
- `--trace-memory` — monitor memory allocations (v0.3+)
- `--profile-instructions` — frequency profiler (v0.3+)
- `--disable-gc` — disable Python GC during exploration (v0.3+)
- `--no-status`
- `--coverage-output FILE` (v0.3+ lcov)

*Experimental:*
- `--symbolic-jump`
- `--flamegraph` — produces `call-flamegraph.svg`, searchable SVG (v0.3+)
- `solx` integration — LLVM-based Solidity compiler as drop-in `solc` replacement via Foundry profile (experimental, v0.3+)
- Future frontends — **Vyper** and **Huff** support is on the roadmap (currently Solidity/Foundry only).

**halmos cheatcodes** (`cheatcodes.py`):

*svm — symbolic value creation:*
- `svm.createUint(bits, name)`, `svm.createUint256(name)`, `svm.createUint256(name, min, max)`
- `svm.createInt(bits, name)`, `svm.createInt256(name)`
- `svm.createBytes(len, name)`, `svm.createString(len, name)`
- `svm.createBytes4(name)`, `svm.createBytes32(name)`
- `svm.createAddress(name)`, `svm.createBool(name)`
- `svm.createCalldata(addr)`, `createCalldata(addr, includeView)`, `createCalldata(name)`, `createCalldata(filename, contract)`, `createCalldata(filename, contract, includeView)`

*svm — storage:*
- `svm.enableSymbolicStorage(addr)` — selector `0xDC00BA4D`; make all storage of `addr` symbolic
- `svm.snapshotStorage(addr)` — selector `0x5DBB8438`; digest hash
- `svm.snapshotState()` — selector `0x9CD23835`; full state digest
- `svm.setArbitraryStorage(addr)` — alias / v0.3+ variant of `enableSymbolicStorage`

*svm — selector reference (v0.3+):*
- `createUint(uint256,string)` — `0x66830DFA`
- `createUint256(string)` — `0xBC7BEEFC`
- `createUint256(string,uint256,uint256)` — `0x3B7A1CA7` (with min/max bound)
- `createInt(uint256,string)` — `0x49B9C7D4`
- `createInt256(string)` — `0xC2CE6AED`
- `createBytes(uint256,string)` — `0xEEF5311D`
- `createString(uint256,string)` — `0xCE68656C`
- `createBytes4(string)` — `0xDE143925`
- `createBytes32(string)` — `0xBF72FA66`
- `createAddress(string)` — `0x3B0FA01B`
- `createBool(string)` — `0x6E0BB659`
- `createCalldata(address)` — `0xB4E9E81C`
- `createCalldata(address,bool)` — `0x49D66B01` (includeView flag)
- `createCalldata(string)` — `0xBE92D5A2`
- `createCalldata(string,bool)` — `0xDEEF391B`
- `createCalldata(string,string)` — `0x88298B32` (filename, contract)
- `createCalldata(string,string,bool)` — `0x607C5C90` (filename, contract, includeView)

*hevm-compatible (vm.* / hevm prefix):*
- `prank(addr)`, `prank(addr, origin)`, `startPrank`, `stopPrank`
- `warp(uint)`, `roll(uint)`, `fee(uint)`, `coinbase(addr)`, `chainId(uint)`, `difficulty(uint)`, `prevrandao(bytes32)`
- `deal(addr, uint)`, `store(addr, slot, value)`, `load(addr, slot)`, `etch(addr, code)`
- `expectRevert()` (limited), `assume(bool)`
- `setEnv` plus `envBool/Uint/Int/Address/Bytes32/Bytes/String` + array and `envOr*` variants
- `envExists(name)`
- `ffi(string[])` — gated by `--ffi`
- `addr(uint privateKey)`, `sign(uint privateKey, bytes32 digest)`, `getCode(string)`, `label(addr, string)` — Foundry compatibility helpers
- `targetContract(addr)`, `targetSelector(...)`, `targetSender(addr)` — invariant scope
- `randomUint(uint min, uint max)`, `randomAddress()`, `randomBytes(uint)`, `randomBool()`, `randomInt()`  — concrete-random helpers (v0.3+ expanded)

*EIP-1153 transient storage opcodes (v0.2.6+):*
- `TLOAD` (0x5C), `TSTORE` (0x5D) — modeled with a per-call-frame Z3 Array, cleared at top-level call exit.

*Supported Foundry cheatcode reference:* the wiki page `a16z/halmos/wiki/Supported-Foundry-Cheatcodes` enumerates the full compatibility matrix; parity tests must mirror that table.

**`check_` discovery convention:**
- Default prefix `(check|invariant)_` set via regex in `--function`.
- A function `check_foo(uint a, address b)` makes `a`, `b` symbolic (treated as fresh BitVec256 / Address); execution explored to all reachable states; any `assert(...)` violation or panic in `--panic-error-codes` causes `[FAIL]`.
- `invariant_foo()` — discovered separately, run after symbolic call sequences of length `--invariant-depth`.

**Loop handling:**
- Bounded by `--loop N` (default 2). The same back-edge is allowed up to N traversals per path.
- If exceeded, Halmos emits a warning suggesting to bump `--loop`.
- vm.assume helps prune impossible loop iterations.

## Engineering hard parts

**CALL handling.** The hardest. For internal calls (same contract or known contract code), straightforward recursive execution. For external calls:
- If target is known concrete address with known code → recurse.
- If target is symbolic → unsolvable in general; Halmos either errors, or with `--symbolic-jump` tries to resolve to a small set of candidates.
- DELEGATECALL with a symbolic target especially nasty; Halmos requires the target to be enumerable.
- The `createCalldata(addr)` approach (canonical pattern) symbolically enumerates the function selector via case-split on the 4 bytes, then runs concrete code with symbolic args — avoids the symbolic-target issue.

**Loop bounding & state explosion.**
- Default `--loop 2` means a `for (uint i; i<n; i++)` is unrolled twice. Anything more requires the user to either prove via invariant or bump bound.
- vm.assume to constrain `n` (e.g., `vm.assume(n <= 3)`).
- Path width capped by `--width`; depth capped by `--depth`.
- The "exponential blowup" mitigation: shared solver scopes (path branching = `solver.push()`), deferred constraint addition (don't add until needed), unsat result caching across paths.

**Symbolic keccak.** Keccak is non-linear and not solver-friendly. Halmos models it with an uninterpreted function `K(args...) → bytes32` and adds axioms:
- Injectivity: `K(x) == K(y) → x == y` (limited to seen pairs to avoid axiom blowup).
- Concrete preimages get concrete hash values.
- For `keccak(key . slot)` patterns (Solidity mapping storage), Halmos detects and short-circuits to a slot-name abstraction.

**State explosion mitigations:**
- DFS with chronological backtracking.
- Lazy constraint propagation.
- Solver-level: `--solver yices` (default v0.3+, 3-5x faster than z3 on these queries), `--cache-solver` for unsat dedup.
- Parallel solver threads (`--solver-threads`).
- Early exit (`--early-exit`).
- `--smt-exp-by-const N` — exponentiation by constants is precomputed up to bound rather than relying on solver theory.

**Invariant exploration.** For depth D and K target functions, naive exploration is K^D paths × symbolic args each. Halmos prunes by:
- Skipping call sequences whose pre-state is equivalent (`snapshotState` hash).
- Targeted invariants — only re-evaluating invariants whose dependencies (read storage slots) intersect with the just-modified slots.

## Library mapping (Python original / Rust target)

| Need | Python (original) | Rust (clone) |
|---|---|---|
| SMT solver | `z3-solver`, optional `yices2-py`, `cvc5`, `bitwuzla` | `z3` crate (libz3 bindings), or `yices2-sys` |
| EVM execution | `pyevmasm` + custom interpreter | adapt revm's `Interpreter` with custom `Stack` storing `Symbolic` enum |
| EVM types | `eth-abi`, `eth-utils`, `eth-hash` | `alloy-sol-types`, `alloy-dyn-abi` |
| Build artifacts | reads Foundry's `out/` JSON | `foundry-compilers` |
| CLI | argparse | clap |
| Parallel | multiprocessing, concurrent.futures | rayon (paths), tokio (async solver) |
| Config | tomli, pydantic | serde + toml |
| Logging | logging + rich | tracing + tracing-subscriber |

Big rewrite win for Rust: pattern matching is gorgeous for opcode dispatch; revm's `Interpreter` trait can be subclassed (custom `Inspector`-like trait). Downside: maintaining symbolic-state semantics through revm requires forking it or implementing a parallel symbolic interpreter (a16z chose Python for ease of prototyping; in Rust you commit upfront).

## Validation test corpus

- **`tests/regression/`** in halmos repo — categorized subdirectories:
  - `loop/`, `prank/`, `calls/`, `storage/`, `symbolic_storage/`, `invariant/`, `setup/`, `snapshot/`, `time/`, `arrays/`, `dynamic/`, `struct/`, `error/`, `factory/`, `fmp/` (free memory pointer), `hashes/`, `libraries/`, `encode/`
- **`examples/simple/`** — known counterexample (testTotalPriceBuggy producing overflow); used in docs.
- **`tests/test_*.py`** — unit tests for sevm, bytevec, bitvec, mapper, traces.
- **Solady, Solmate, OZ libraries** — community-run halmos checks of common library functions; useful regression set.

## 2024–2026 state

- **v0.1.0 (2023):** initial release.
- **v0.2.x (2024):** SMT performance, `createCalldata` for backdoor checks, coverage and `--trace-events`, debugger improvements.
- **v0.3.0 (early 2025):** stateful **invariant testing** (most-requested), coverage reports (lcov), interactive flamegraphs, 32x faster EVM interpreter, solver-by-name (`--solver cvc5`), Yices replaces Z3 as default (3-5x faster), solx (LLVM-based Solidity) support, env/random cheatcodes, live progress.
- **2025–2026:** target solver-portfolio, model exporters for replay in Foundry, improved `--invariant-depth` heuristics. Continued interplay with **KEVM/Kontrol** (Runtime Verification) — Kontrol uses K-framework's KEVM semantics, slower but more rigorous. **hevm** (Brock) is the spiritual predecessor in Haskell; CAV 2024 paper "Hevm, a Fast Symbolic Execution Framework for EVM Bytecode" describes shared design space.
- Halmos integrates with Foundry's "symbolic test runner hook" promised in Foundry's roadmap.

### Research update — 2026-05-30

Cross-checked against upstream `a16z/halmos` (v0.3.3 — latest tagged release on GitHub at this time; 34 total releases; 1k+ stars; 70.4% Python / 29% Solidity) and `a16z/halmos-cheatcodes` companion repo. Gaps closed against the upstream `config.py` / `cheatcodes.py` and the v0.3.0 release-highlights post:

- **Solver default change confirmed** — Yices is the default since v0.3.0 (3-5x faster than Z3 on typical halmos queries). `--solver <name>` auto-discovers installed solvers in PATH / halmos cache and offers installation if missing. Bitwuzla static-binary download added in v0.3.2.
- **Solx (LLVM Solidity) integration** — drop-in `solc` replacement via Foundry profile; lancer-halmos must accept the same Foundry build artifacts even when `solx` produced them.
- **Coverage report** — `--coverage-output lcov.info` emits standard lcov for `genhtml` / VSCode Coverage Gutters; this is the only currently supported coverage format.
- **Flamegraph** — `--flamegraph` produces interactive `call-flamegraph.svg` (searchable for "FAIL" to jump to counterexample sequences during invariant runs).
- **New v0.3+ debug/profile flags** — `--dump-smt-directory`, `--trace-memory`, `--profile-instructions`, `--disable-gc` added to the parity catalog.
- **Transient storage** — `TLOAD`/`TSTORE` (EIP-1153) supported since v0.2.6; must be in the SVM opcode table.
- **Random/env cheatcode family** — `randomAddress`, `randomBool`, `randomBytes`, `randomInt`, `randomUint` + `envExists`, `envOr*` array forms confirmed; concrete (not symbolic) values backed by seeded RNG.
- **Snapshot cheatcodes** — `svm.snapshotStorage(addr)` (selector `0x5DBB8438`) and `svm.snapshotState()` (selector `0x9CD23835`) added in v0.2.3; used for invariant state-dedup in v0.3.
- **`createCalldata` overload matrix** — six selectors total (address / address+bool / string / string+bool / string+string / string+string+bool); each maps to a distinct ABI dispatch path that the Rust cheatcode router must implement.
- **`setArbitraryStorage(addr)`** — v0.3+ alias for `enableSymbolicStorage`; both selectors must dispatch.
- **Frontend roadmap** — Vyper and Huff support are on the upstream roadmap; lancer-halmos `core` crate must keep the bytecode frontend pluggable to absorb these later.
- **EVM interpreter 32x speedup (v0.3.0)** — upstream rewrote the dispatch loop; in Rust we should get this "for free" via match-based opcode dispatch + cached BV ops, but parity tests must verify path-equivalence not just final-state.
- **Live progress UX** — ops/sec, paths completed, solver-query progress; mirrors must be plumbed into the Lancer GUI status bar.
- **Installation channels** — upstream now ships via `uv tool install`, Docker `ghcr.io/a16z/halmos:latest`, and pip; lancer-halmos `--cli` should be invocable as a uv-tool-compatible shim for drop-in replacement in existing CI.

## Real-world audit workflows

- **Spec-as-code.** Auditor writes `check_*` properties as Solidity test functions (uses same forge harness). For an AMM: `check_invariantK_afterSwap(uint x, uint y)`.
- **Backdoor checks** (a16z popularized): `check_NoBackdoor(bytes4 selector, bytes args)` proves no calldata can drain a target — `selector` symbolic + `args = svm.createBytes(1024)` — Halmos enumerates the selector space.
- **Numerical edge cases** that fuzzing misses (e.g., `(amount * price) / 1e18 == 0` only when amount * price < 1e18). The dossier example `testTotalPriceBuggy` is the canonical case.
- **Companion to forge fuzz.** Auditor first writes `check_X`; runs forge fuzz for coverage and sanity; runs halmos for deductive proof; if halmos times out, weaken assumptions (`vm.assume`).
- **Solady/Solmate community.** Many low-level math libraries (`FixedPointMathLib`, `SafeTransferLib`) ship with halmos checks in their test suites.

## AI augmentation ideas

- **Spec generation from natural language.** "Prove this AMM constant product holds across swaps." → LLM emits `check_invariantK(...)` template with right vm.assume bounds.
- **Counterexample explanation.** Z3 model values are opaque numbers; LLM contextualizes ("the failure happens when alice provides amount = 2^96 and the multiplication overflows uint96").
- **Loop bound suggestion.** When a path hits `--loop` limit, LLM reads the loop body and suggests a higher bound or an invariant to introduce.
- **Symbolic-friendly refactoring.** LLM rewrites Solidity to avoid known anti-patterns (symbolic CALLDATALOAD offset, infinite-keccak loops).
- **Auto-`createCalldata` for backdoor checks.** Given a contract's role-gating, generate the matching `check_NoBackdoor` invocation.

## Implementation phases (10-week clone — Rust path)

**Week 1 — Z3 binding & EVM types.** Cargo workspace; `z3` crate; define `Symbolic = Concrete(U256) | Sym(BV)` enum; symbolic memory (`ByteVec` analog) + symbolic stack.

**Week 2 — Concrete subset of SEVM.** Implement opcode dispatch for ALL opcodes with concrete-only operands (reuse revm if licenses permit, or hand-roll). Validate vs revm on EVM-tests JSON suite.

**Week 3 — Symbolic operators.** Symbolic ADD/SUB/MUL/DIV/MOD/EXP/LT/GT/EQ/AND/OR/XOR/SHL/SHR/SAR/BYTE on `Symbolic`. Bitwidth-correct via z3 BV ops.

**Week 4 — Path forking.** `JUMPI` with symbolic condition: solver-assisted feasibility check; push two paths to worklist. DFS exploration. Deferred constraint addition.

**Week 5 — Storage model.** Solidity layout (read storageLayout from artifact, model mappings as Z3 Arrays keyed by symbolic preimage). Symbolic keccak with injectivity axioms.

**Week 6 — Calls.** CALL/STATICCALL/DELEGATECALL with concrete targets — recursive frame, new `State`, preserved storage as appropriate. Symbolic target = error w/ TODO.

**Week 7 — Foundry integration.** Load `out/` artifacts; discover `check_*` functions; build symbolic calldata from typed args; run setUp() symbolically; emit per-test PASS/FAIL.

**Week 8 — Cheatcodes.** Implement vm.* (prank, warp, roll, deal, store, load, assume, expectRevert (limited)), svm.* (createUint, createBytes, createAddress, createCalldata, enableSymbolicStorage), envXxx. Cheatcode dispatch via 4-byte selector match on calls to vm address.

**Week 9 — Invariant mode.** Auto-discover `invariant_*` + targetContracts; generate symbolic call sequences up to `--invariant-depth`; assert invariants after each state; counterexample = concrete sequence.

**Week 10 — Reports, parallelism, polish.** lcov coverage output, JSON output (counterexamples), parallel paths via rayon, solver threading, `--early-exit`, `--dump-smt-queries`. Optional flamegraph rendering. Benchmark against halmos's regression suite.

---

## GUI (Lancer-standard pattern)

`lancer-halmos` ships as a **native GUI application** by default. The CLI surface listed in `## Granular feature catalog` is still available behind a `--cli` flag (or via the `lancer-halmos-cli` companion binary), but the **plain `lancer-halmos` invocation opens a native desktop window**, matching every other tool in the Lancer ecosystem. No terminal-only mode.

### Framework

Pure-Rust GUI stack — no JavaScript, no Node, single static binary:

| Crate | Role |
|-------|------|
| `eframe` | Cross-platform window + event loop wrapper around `egui` |
| `egui` | Immediate-mode UI widgets (panels, tables, forms, menus, drag-and-drop) |
| `egui_extras` | Sortable tables, image loaders, syntax highlighting, date pickers |
| `egui_plot` | Charts, graphs, timelines (histograms, activity meters, progress) |
| `rfd` | Native file/folder pickers (open file, save dialog) |
| `directories` | Per-OS config dir (`~/.config/lancer-halmos/`, `%APPDATA%\lancer-halmos\`, etc.) |
| `image` | Screenshot / preview rendering inside egui |
| `arboard` | Clipboard read/write for "copy result" actions |
| `muda` | Native menu bar (Linux / macOS / Windows) |
| `egui-notify` | Toast notifications |

Optional dark/light theme persisted to `lancer-halmos-config.json` via `serde_json`.

### Window layout

Three-pane layout matching the Lancer mothership GUI:

```
┌─────────────────────────────────────────────────────────────────────┐
│  File   Tools   Settings   Help                              [≡]    │
├──────────┬────────────────────────────────────────┬─────────────────┤
│          │                                        │                 │
│  Inputs  │           Main view                    │  Detail pane    │
│  / jobs  │  (table of results / source tree /     │  (full record / │
│  / scope │   findings list / packet list / etc.)  │   bytes / src / │
│          │                                        │   remediation)  │
│          │                                        │                 │
├──────────┴────────────────────────────────────────┴─────────────────┤
│  Status: idle           Items: 0          [Open]  [Run]  [Export]   │
└─────────────────────────────────────────────────────────────────────┘
```

- **Left sidebar (200-300px)** — inputs / queued jobs / scope / target list. Drag-and-drop accepted.
- **Center pane (flexible)** — primary result view appropriate to the tool (table for findings, tree for hierarchical data, code editor for source).
- **Right pane (300-400px, collapsible)** — full detail of the currently-selected item.
- **Top menu bar** — File (Open / Save / Export / Recent / Quit), Tools (per-tool actions), Settings (theme, fonts, integrations), Help (About / Docs).
- **Bottom status bar** — current activity, item counts, primary action buttons.

### Cross-tool integration with Lancer + the other 29 clones

Every Lancer-clone GUI exposes a small local HTTP server on a port auto-allocated at launch (`127.0.0.1:<port>`, written to `%TEMP%/lancer-halmos.port`):

- The main Lancer GUI discovers running tools by scanning `%TEMP%/lancer-*.port` and lists them in its sidebar.
- Right-clicking any item in any tool can "Send to <other Lancer tool>" — the receiving tool fetches the payload via its own HTTP endpoint.
- A future "Lancer Hub" tray shell can launch / focus any of the 30 GUIs from one menu.
- HTTP endpoints exposed:
  - `GET  /v1/state` — current jobs / progress
  - `POST /v1/import` — accept a target / file / record from another Lancer tool
  - `GET  /v1/export?format=json|csv|sarif|markdown` — pull the current result set in a portable format

### Async work + responsiveness

- Long-running scans run on a Tokio task pool; the GUI thread only renders.
- Progress propagates via `crossbeam::channel` from worker → UI.
- A `Stop` button cancels in-flight work via a `CancellationToken`.
- All file I/O / network I/O / subprocess work goes through async channels — the egui thread never blocks.

### Build output

The existing `build.bat` / `build-windows.bat` / `build-linux.sh` already produce a single binary. With `eframe` linked, the same binary is the GUI app.

- Windows: `build\lancer-halmos.exe` (double-click opens the GUI window).
- Linux: `build/lancer-halmos` (also installable as a `.desktop` entry via `build-linux.sh --install`).
- macOS: `build/lancer-halmos` (bundled into `lancer-halmos.app` via `cargo-bundle` in the `build-mac.sh` companion).

For CI / headless / scripting, pass `--cli` to fall through to the CLI surface from `## Granular feature catalog`.

## Build Setup (Lancer-standard pattern)

This clone follows the same build pattern as the main Lancer project — single `.exe` output via `build.bat` on Windows, `.so/elf` via `build-linux.sh` on Linux.

### Project layout

```
lancer-halmos/
├── Cargo.toml              # single-crate Rust project
├── Cargo.lock              # committed (binary, not library)
├── src/
│   └── main.rs             # entry point (scaffold)
├── build.bat               # Windows build → build/lancer-halmos.exe
├── build-windows.bat       # Windows packaged dist build → dist/lancer-halmos-windows-x86_64/
├── build-linux.sh          # Linux build → build/lancer-halmos
├── .gitignore              # plan.md (local-only) + target/ + build/ + dist/
├── README.md               # public-facing (pushed to GitHub)
└── plan.md                 # this file (gitignored — local blueprint, never pushed)
```

### Build commands

**Windows (double-click `build.bat`):**
```
build.bat
```
Produces `build\lancer-halmos.exe`. Pauses at end so the window stays open.

**Windows (packaged dist):**
```
build-windows.bat
```
Produces `dist\lancer-halmos-windows-x86_64\bin\lancer-halmos.exe` plus LICENSE/README — ready to zip.

**Linux / macOS:**
```bash
./build-linux.sh
```
Produces `build/lancer-halmos`.

### Requirements
- Rust toolchain (https://rustup.rs)
- Windows: Visual C++ Build Tools 2019/2022 (needed by some crates)

### CI

The build pattern is intentionally identical across Lancer and all 19 clones, so a single Jenkins/GitHub Actions matrix can build everything by calling `build-windows.bat` or `build-linux.sh` per repo.
