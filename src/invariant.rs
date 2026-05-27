//! Invariant testing mode.
//!
//! For `invariant_*` functions: symbolically explore sequences of calls
//! of length --invariant-depth to target contracts, then assert the invariant
//! after each state transition.

use primitive_types::U256;
use std::collections::HashMap;

use crate::abi::AbiFunction;
use crate::artifacts::Contract;
use crate::calldata::build_symbolic_message;
use crate::config::Config;
use crate::exceptions::HaltReason;
use crate::sevm::SEVM;
use crate::solver::Solver;
use crate::state::{BlockCtx, Frame, Message};
use crate::storage::WorldState;
use crate::symbolic::{fresh_var, Expr};

/// Result for a single invariant test
#[derive(Debug)]
pub struct InvariantResult {
    pub invariant_name: String,
    pub passed: bool,
    pub counterexample: Option<Vec<CallStep>>,
    pub message: String,
}

/// A single step in a counterexample call sequence
#[derive(Debug, Clone)]
pub struct CallStep {
    pub target: [u8; 20],
    pub function_name: String,
    pub args: Vec<U256>,
}

/// Run all invariant_ functions in a contract
pub fn run_invariant_tests(
    contract: &Contract,
    target_contracts: &[([u8; 20], &Contract)],
    world: WorldState,
    block: BlockCtx,
    config: &Config,
    solver: &Solver,
) -> Vec<InvariantResult> {
    let invariant_fns: Vec<&AbiFunction> = contract.abi.iter()
        .filter(|f| f.name.starts_with("invariant_"))
        .collect();

    let target_fns: Vec<(&[u8; 20], &AbiFunction)> = target_contracts.iter()
        .flat_map(|(addr, c)| {
            c.abi.iter()
                .filter(|f| !f.name.starts_with("check_") && !f.name.starts_with("invariant_"))
                .filter(|f| matches!(f.state_mutability,
                    crate::abi::StateMutability::NonPayable | crate::abi::StateMutability::Payable))
                .map(move |f| (addr, f))
        })
        .collect();

    let sevm = SEVM::new(config, solver);
    let mut results = Vec::new();

    for inv_fn in invariant_fns {
        let result = run_single_invariant(
            inv_fn,
            contract,
            &target_fns,
            world.clone(),
            block.clone(),
            config,
            &sevm,
            solver,
        );
        results.push(result);
    }

    results
}

fn run_single_invariant(
    inv_fn: &AbiFunction,
    inv_contract: &Contract,
    target_fns: &[(&[u8; 20], &AbiFunction)],
    initial_world: WorldState,
    block: BlockCtx,
    config: &Config,
    sevm: &SEVM,
    solver: &Solver,
) -> InvariantResult {
    let depth = config.invariant_depth;
    let inv_addr = [0x11u8; 20]; // test contract address
    let caller_addr = [0xaa; 20];

    // Explore call sequences of length `depth`
    struct State {
        world: WorldState,
        call_seq: Vec<CallStep>,
    }

    let initial = State {
        world: initial_world,
        call_seq: vec![],
    };

    let mut worklist = vec![initial];

    while let Some(state) = worklist.pop() {
        if state.call_seq.len() >= depth {
            continue;
        }

        // Try each target function
        for (target_addr, func) in target_fns.iter() {
            let msg = build_symbolic_message(func, **target_addr, caller_addr);
            let code = vec![]; // TODO: get code for target
            let frame = Frame::new(code, msg, state.world.clone(), block.clone());
            let frames = sevm.run(frame);

            for completed_frame in frames {
                // After state transition, check invariant
                let inv_result = check_invariant(
                    inv_fn,
                    inv_contract,
                    &completed_frame.world,
                    &block,
                    inv_addr,
                    caller_addr,
                    sevm,
                    solver,
                );

                if let Some(counterexample_model) = inv_result {
                    let mut seq = state.call_seq.clone();
                    seq.push(CallStep {
                        target: **target_addr,
                        function_name: func.name.clone(),
                        args: vec![],
                    });
                    return InvariantResult {
                        invariant_name: inv_fn.name.clone(),
                        passed: false,
                        counterexample: Some(seq),
                        message: format!("Invariant {} violated", inv_fn.name),
                    };
                }

                // Push new state for deeper exploration
                if state.call_seq.len() + 1 < depth {
                    let mut new_seq = state.call_seq.clone();
                    new_seq.push(CallStep {
                        target: **target_addr,
                        function_name: func.name.clone(),
                        args: vec![],
                    });
                    worklist.push(State {
                        world: completed_frame.world,
                        call_seq: new_seq,
                    });
                }
            }
        }
    }

    InvariantResult {
        invariant_name: inv_fn.name.clone(),
        passed: true,
        counterexample: None,
        message: format!("[PASS] {} (invariant-depth={})", inv_fn.name, depth),
    }
}

/// Run the invariant function on the current world state and check if it holds
fn check_invariant(
    inv_fn: &AbiFunction,
    inv_contract: &Contract,
    world: &WorldState,
    block: &BlockCtx,
    inv_addr: [u8; 20],
    caller: [u8; 20],
    sevm: &SEVM,
    solver: &Solver,
) -> Option<crate::solver::SolverModel> {
    let selector = inv_fn.selector();
    let calldata = selector.to_vec();
    let msg = Message {
        caller,
        callee: inv_addr,
        origin: caller,
        callvalue: Expr::Concrete(U256::zero()),
        calldata,
        calldata_sym: vec![],
        gas: 30_000_000,
        is_static: true,
        depth: 0,
    };

    let frame = Frame::new(
        inv_contract.deployed_bytecode.clone(),
        msg,
        world.clone(),
        block.clone(),
    );

    let results = sevm.run(frame);

    for result in results {
        if let Some(res) = &result.result {
            if !res.success {
                // Invariant reverted — check if this path is satisfiable
                let (sat, model) = solver.check_sat_with_model(&result.path, &[]);
                if sat == crate::solver::SatResult::Sat {
                    return model;
                }
            }
        }
    }
    None
}
