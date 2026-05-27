//! Execution trace builder — per-path trace of opcodes and events.

use primitive_types::U256;
use crate::symbolic::Expr;
use crate::state::{Frame, Log};
use crate::opcodes;

/// A single trace event
#[derive(Debug, Clone)]
pub enum TraceEvent {
    Opcode { pc: usize, op: u8, stack_top: Option<Expr> },
    Call { caller: [u8; 20], callee: [u8; 20], value: Expr, selector: Option<[u8; 4]> },
    Return { success: bool, data_len: usize },
    Log { topics: Vec<Expr>, data_len: usize },
    SStore { slot: Expr, value: Expr },
    SLoad { slot: Expr, value: Expr },
    Assert { message: String },
}

#[derive(Debug, Clone, Default)]
pub struct Trace {
    pub events: Vec<TraceEvent>,
}

impl Trace {
    pub fn new() -> Self { Self::default() }

    pub fn push(&mut self, event: TraceEvent) {
        self.events.push(event);
    }

    pub fn opcode(&mut self, pc: usize, op: u8, stack_top: Option<Expr>) {
        self.events.push(TraceEvent::Opcode { pc, op, stack_top });
    }

    pub fn call(&mut self, caller: [u8; 20], callee: [u8; 20], value: Expr, selector: Option<[u8; 4]>) {
        self.events.push(TraceEvent::Call { caller, callee, value, selector });
    }

    pub fn log_event(&mut self, topics: Vec<Expr>, data_len: usize) {
        self.events.push(TraceEvent::Log { topics, data_len });
    }
}

/// Build a human-readable trace from a completed Frame
pub fn format_trace(frame: &Frame) -> String {
    let mut out = String::new();
    for log in &frame.logs {
        out.push_str(&format!(
            "  emit {} topics={}\n",
            hex::encode(log.address),
            log.topics.len()
        ));
    }
    if let Some(res) = &frame.result {
        match &res.halt {
            crate::exceptions::HaltReason::Stop => out.push_str("  [STOP]\n"),
            crate::exceptions::HaltReason::Return(d) => {
                out.push_str(&format!("  [RETURN] {} bytes\n", d.len()));
            }
            crate::exceptions::HaltReason::Revert(d) => {
                let reason = crate::exceptions::decode_revert(d);
                out.push_str(&format!("  [REVERT] {}\n", reason));
            }
            crate::exceptions::HaltReason::SelfDestruct => out.push_str("  [SELFDESTRUCT]\n"),
        }
    }
    out
}

/// Extract the concrete counterexample from a solver model + path frame
pub fn format_counterexample(
    frame: &Frame,
    model: &crate::solver::SolverModel,
    func_name: &str,
) -> String {
    let mut out = format!("  Counterexample for {}:\n", func_name);
    for (name, val) in &model.assignments {
        out.push_str(&format!("    {} = {}\n", name, val));
    }
    out
}
