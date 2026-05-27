use thiserror::Error;
use primitive_types::U256;

/// Reason a path terminated normally (not an error)
#[derive(Debug, Clone, PartialEq)]
pub enum HaltReason {
    Stop,
    Return(Vec<u8>),
    Revert(Vec<u8>),
    SelfDestruct,
}

/// Fatal execution errors (path is infeasible or invalid)
#[derive(Debug, Clone, Error, PartialEq)]
pub enum EvmError {
    #[error("stack underflow")]
    StackUnderflow,
    #[error("stack overflow")]
    StackOverflow,
    #[error("invalid opcode: {0:#x}")]
    InvalidOpcode(u8),
    #[error("invalid jump destination: {0}")]
    InvalidJump(U256),
    #[error("out of gas")]
    OutOfGas,
    #[error("memory access out of bounds")]
    MemoryOutOfBounds,
    #[error("call depth exceeded")]
    CallDepthExceeded,
    #[error("static state change")]
    StaticStateChange,
    #[error("write protection")]
    WriteProtection,
    #[error("symbolic jump target (use --symbolic-jump)")]
    SymbolicJump,
    #[error("symbolic call target")]
    SymbolicCall,
    #[error("loop bound exceeded (--loop)")]
    LoopBound,
    #[error("path width exceeded (--width)")]
    PathWidthExceeded,
    #[error("path depth exceeded (--depth)")]
    PathDepthExceeded,
    #[error("assertion failed: {0}")]
    AssertionFailed(String),
    #[error("panic: error code {0:#x}")]
    Panic(U256),
    #[error("solver error: {0}")]
    SolverError(String),
    #[error("infeasible path")]
    Infeasible,
}

/// Result of one execution step
#[derive(Debug)]
pub enum StepResult {
    Continue,
    Fork(Vec<crate::state::Frame>),
    Halt(HaltReason),
    Error(EvmError),
}

/// Standard panic selector (Solidity 0.8+): Panic(uint256)
pub const PANIC_SELECTOR: [u8; 4] = [0x4e, 0x48, 0x7b, 0x71];
/// Standard revert selector: Error(string)
pub const ERROR_SELECTOR: [u8; 4] = [0x08, 0xc3, 0x79, 0xa0];

/// Decode revert data to check for assertion failure or panic
pub fn decode_revert(data: &[u8]) -> String {
    if data.len() >= 4 {
        if data[..4] == PANIC_SELECTOR && data.len() >= 36 {
            let code = U256::from_big_endian(&data[4..36]);
            return format!("Panic({:#x})", code);
        }
        if data[..4] == ERROR_SELECTOR && data.len() >= 68 {
            if let Ok(s) = std::str::from_utf8(&data[68..]) {
                return format!("Error(\"{}\")", s.trim_end_matches('\0'));
            }
        }
    }
    format!("revert({})", hex::encode(data))
}
