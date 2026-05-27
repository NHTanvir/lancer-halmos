//! EVM execution state: Stack, State, Path, Message, CallContext.

use primitive_types::U256;
use std::collections::HashMap;
use crate::symbolic::{Expr, Pred};
use crate::memory::Memory;
use crate::storage::WorldState;
use crate::exceptions::{EvmError, HaltReason};

pub const MAX_STACK_DEPTH: usize = 1024;

// ─── Stack ────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Default)]
pub struct Stack(Vec<Expr>);

impl Stack {
    pub fn push(&mut self, val: Expr) -> Result<(), EvmError> {
        if self.0.len() >= MAX_STACK_DEPTH {
            return Err(EvmError::StackOverflow);
        }
        self.0.push(val);
        Ok(())
    }

    pub fn pop(&mut self) -> Result<Expr, EvmError> {
        self.0.pop().ok_or(EvmError::StackUnderflow)
    }

    pub fn peek(&self, idx: usize) -> Result<&Expr, EvmError> {
        let len = self.0.len();
        if idx >= len { return Err(EvmError::StackUnderflow); }
        Ok(&self.0[len - 1 - idx])
    }

    pub fn dup(&mut self, n: usize) -> Result<(), EvmError> {
        // DUP1 = n=1, duplicates top
        if n == 0 || n > 16 { return Err(EvmError::StackUnderflow); }
        let len = self.0.len();
        if n > len { return Err(EvmError::StackUnderflow); }
        let val = self.0[len - n].clone();
        self.push(val)
    }

    pub fn swap(&mut self, n: usize) -> Result<(), EvmError> {
        // SWAP1 = n=1, swaps top with 2nd
        if n == 0 || n > 16 { return Err(EvmError::StackUnderflow); }
        let len = self.0.len();
        if n >= len { return Err(EvmError::StackUnderflow); }
        self.0.swap(len - 1, len - 1 - n);
        Ok(())
    }

    pub fn len(&self) -> usize { self.0.len() }
    pub fn is_empty(&self) -> bool { self.0.is_empty() }
}

// ─── Call environment ─────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct Message {
    pub caller: [u8; 20],
    pub callee: [u8; 20],
    pub origin: [u8; 20],
    pub callvalue: Expr,
    pub calldata: Vec<u8>,     // concrete calldata bytes
    pub calldata_sym: Vec<Expr>, // symbolic calldata words (per 32-byte slot)
    pub gas: u64,
    pub is_static: bool,
    pub depth: usize,
}

impl Default for Message {
    fn default() -> Self {
        Self {
            caller: [0u8; 20],
            callee: [0u8; 20],
            origin: [0u8; 20],
            callvalue: Expr::Concrete(U256::zero()),
            calldata: vec![],
            calldata_sym: vec![],
            gas: 30_000_000,
            is_static: false,
            depth: 0,
        }
    }
}

// ─── Block context ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct BlockCtx {
    pub coinbase: [u8; 20],
    pub timestamp: Expr,
    pub number: Expr,
    pub difficulty: Expr,
    pub gaslimit: u64,
    pub chainid: u64,
    pub basefee: Expr,
}

impl Default for BlockCtx {
    fn default() -> Self {
        Self {
            coinbase: [0u8; 20],
            timestamp: Expr::Concrete(U256::zero()),
            number: Expr::Concrete(U256::zero()),
            difficulty: Expr::Concrete(U256::zero()),
            gaslimit: 30_000_000,
            chainid: 1,
            basefee: Expr::Concrete(U256::zero()),
        }
    }
}

// ─── Path ─────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Default)]
pub struct Path {
    /// Accumulated path constraints (all must be satisfiable)
    pub constraints: Vec<Pred>,
    /// Jump history: (pc, times_taken) for loop bounding
    pub jump_counts: HashMap<usize, usize>,
    /// Step count for depth bounding
    pub steps: usize,
}

impl Path {
    pub fn new() -> Self { Self::default() }

    pub fn add_constraint(&mut self, p: Pred) {
        match p {
            Pred::True => {} // trivially satisfied
            other => self.constraints.push(other),
        }
    }

    pub fn record_jump(&mut self, pc: usize) -> usize {
        let count = self.jump_counts.entry(pc).or_insert(0);
        *count += 1;
        *count
    }

    pub fn all_constraints_smt2(&self) -> String {
        if self.constraints.is_empty() {
            return "true".to_string();
        }
        if self.constraints.len() == 1 {
            return self.constraints[0].to_smt2();
        }
        let parts: Vec<_> = self.constraints.iter().map(|p| p.to_smt2()).collect();
        format!("(and {})", parts.join(" "))
    }

    pub fn free_vars(&self) -> Vec<String> {
        let mut vars = Vec::new();
        for c in &self.constraints {
            vars.extend(c.free_vars());
        }
        vars.sort();
        vars.dedup();
        vars
    }
}

// ─── EVM execution state ──────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct EvmState {
    pub pc: usize,
    pub stack: Stack,
    pub memory: Memory,
    pub returndata: Vec<u8>,
    pub stopped: bool,
}

impl Default for EvmState {
    fn default() -> Self {
        Self {
            pc: 0,
            stack: Stack::default(),
            memory: Memory::new(),
            returndata: vec![],
            stopped: false,
        }
    }
}

// ─── Execution frame (a complete path snapshot) ───────────────────────────────

#[derive(Debug, Clone)]
pub struct Frame {
    pub evm: EvmState,
    pub path: Path,
    pub world: WorldState,
    pub msg: Message,
    pub block: BlockCtx,
    /// The bytecode being executed
    pub code: Vec<u8>,
    /// Return data destination (for CALL return)
    pub ret_offset: Option<usize>,
    pub ret_len: Option<usize>,
    /// Logs emitted in this path
    pub logs: Vec<Log>,
    /// Call result: only set when frame halts
    pub result: Option<FrameResult>,
}

impl Frame {
    pub fn new(code: Vec<u8>, msg: Message, world: WorldState, block: BlockCtx) -> Self {
        Self {
            evm: EvmState::default(),
            path: Path::new(),
            world,
            msg,
            block,
            code,
            ret_offset: None,
            ret_len: None,
            logs: vec![],
            result: None,
        }
    }
}

#[derive(Debug, Clone)]
pub struct FrameResult {
    pub halt: HaltReason,
    pub return_data: Vec<u8>,
    pub success: bool,
}

#[derive(Debug, Clone)]
pub struct Log {
    pub address: [u8; 20],
    pub topics: Vec<Expr>,
    pub data: Vec<u8>,
}
