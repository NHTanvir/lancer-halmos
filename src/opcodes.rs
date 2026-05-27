// EVM opcode constants
pub const STOP: u8 = 0x00;
pub const ADD: u8 = 0x01;
pub const MUL: u8 = 0x02;
pub const SUB: u8 = 0x03;
pub const DIV: u8 = 0x04;
pub const SDIV: u8 = 0x05;
pub const MOD: u8 = 0x06;
pub const SMOD: u8 = 0x07;
pub const ADDMOD: u8 = 0x08;
pub const MULMOD: u8 = 0x09;
pub const EXP: u8 = 0x0a;
pub const SIGNEXTEND: u8 = 0x0b;

pub const LT: u8 = 0x10;
pub const GT: u8 = 0x11;
pub const SLT: u8 = 0x12;
pub const SGT: u8 = 0x13;
pub const EQ: u8 = 0x14;
pub const ISZERO: u8 = 0x15;
pub const AND: u8 = 0x16;
pub const OR: u8 = 0x17;
pub const XOR: u8 = 0x18;
pub const NOT: u8 = 0x19;
pub const BYTE: u8 = 0x1a;
pub const SHL: u8 = 0x1b;
pub const SHR: u8 = 0x1c;
pub const SAR: u8 = 0x1d;

pub const KECCAK256: u8 = 0x20;

pub const ADDRESS: u8 = 0x30;
pub const BALANCE: u8 = 0x31;
pub const ORIGIN: u8 = 0x32;
pub const CALLER: u8 = 0x33;
pub const CALLVALUE: u8 = 0x34;
pub const CALLDATALOAD: u8 = 0x35;
pub const CALLDATASIZE: u8 = 0x36;
pub const CALLDATACOPY: u8 = 0x37;
pub const CODESIZE: u8 = 0x38;
pub const CODECOPY: u8 = 0x39;
pub const GASPRICE: u8 = 0x3a;
pub const EXTCODESIZE: u8 = 0x3b;
pub const EXTCODECOPY: u8 = 0x3c;
pub const RETURNDATASIZE: u8 = 0x3d;
pub const RETURNDATACOPY: u8 = 0x3e;
pub const EXTCODEHASH: u8 = 0x3f;

pub const BLOCKHASH: u8 = 0x40;
pub const COINBASE: u8 = 0x41;
pub const TIMESTAMP: u8 = 0x42;
pub const NUMBER: u8 = 0x43;
pub const DIFFICULTY: u8 = 0x44; // also PREVRANDAO post-merge
pub const GASLIMIT: u8 = 0x45;
pub const CHAINID: u8 = 0x46;
pub const SELFBALANCE: u8 = 0x47;
pub const BASEFEE: u8 = 0x48;

pub const POP: u8 = 0x50;
pub const MLOAD: u8 = 0x51;
pub const MSTORE: u8 = 0x52;
pub const MSTORE8: u8 = 0x53;
pub const SLOAD: u8 = 0x54;
pub const SSTORE: u8 = 0x55;
pub const JUMP: u8 = 0x56;
pub const JUMPI: u8 = 0x57;
pub const PC: u8 = 0x58;
pub const MSIZE: u8 = 0x59;
pub const GAS: u8 = 0x5a;
pub const JUMPDEST: u8 = 0x5b;
pub const PUSH0: u8 = 0x5f; // EIP-3855

// PUSH1..PUSH32
pub const PUSH1: u8 = 0x60;
pub const PUSH32: u8 = 0x7f;

// DUP1..DUP16
pub const DUP1: u8 = 0x80;
pub const DUP16: u8 = 0x8f;

// SWAP1..SWAP16
pub const SWAP1: u8 = 0x90;
pub const SWAP16: u8 = 0x9f;

// LOG0..LOG4
pub const LOG0: u8 = 0xa0;
pub const LOG4: u8 = 0xa4;

pub const CREATE: u8 = 0xf0;
pub const CALL: u8 = 0xf1;
pub const CALLCODE: u8 = 0xf2;
pub const RETURN: u8 = 0xf3;
pub const DELEGATECALL: u8 = 0xf4;
pub const CREATE2: u8 = 0xf5;
pub const STATICCALL: u8 = 0xfa;
pub const REVERT: u8 = 0xfd;
pub const INVALID: u8 = 0xfe;
pub const SELFDESTRUCT: u8 = 0xff;

/// Number of bytes pushed by PUSH1..PUSH32
pub fn push_size(opcode: u8) -> Option<usize> {
    if opcode >= PUSH1 && opcode <= PUSH32 {
        Some((opcode - PUSH1 + 1) as usize)
    } else if opcode == PUSH0 {
        Some(0)
    } else {
        None
    }
}

/// Human-readable opcode name (for traces)
pub fn name(opcode: u8) -> &'static str {
    match opcode {
        STOP => "STOP", ADD => "ADD", MUL => "MUL", SUB => "SUB",
        DIV => "DIV", SDIV => "SDIV", MOD => "MOD", SMOD => "SMOD",
        ADDMOD => "ADDMOD", MULMOD => "MULMOD", EXP => "EXP",
        SIGNEXTEND => "SIGNEXTEND",
        LT => "LT", GT => "GT", SLT => "SLT", SGT => "SGT",
        EQ => "EQ", ISZERO => "ISZERO",
        AND => "AND", OR => "OR", XOR => "XOR", NOT => "NOT",
        BYTE => "BYTE", SHL => "SHL", SHR => "SHR", SAR => "SAR",
        KECCAK256 => "KECCAK256",
        ADDRESS => "ADDRESS", BALANCE => "BALANCE", ORIGIN => "ORIGIN",
        CALLER => "CALLER", CALLVALUE => "CALLVALUE",
        CALLDATALOAD => "CALLDATALOAD", CALLDATASIZE => "CALLDATASIZE",
        CALLDATACOPY => "CALLDATACOPY", CODESIZE => "CODESIZE",
        CODECOPY => "CODECOPY", GASPRICE => "GASPRICE",
        EXTCODESIZE => "EXTCODESIZE", EXTCODECOPY => "EXTCODECOPY",
        RETURNDATASIZE => "RETURNDATASIZE", RETURNDATACOPY => "RETURNDATACOPY",
        EXTCODEHASH => "EXTCODEHASH",
        BLOCKHASH => "BLOCKHASH", COINBASE => "COINBASE",
        TIMESTAMP => "TIMESTAMP", NUMBER => "NUMBER",
        DIFFICULTY => "DIFFICULTY", GASLIMIT => "GASLIMIT",
        CHAINID => "CHAINID", SELFBALANCE => "SELFBALANCE", BASEFEE => "BASEFEE",
        POP => "POP", MLOAD => "MLOAD", MSTORE => "MSTORE", MSTORE8 => "MSTORE8",
        SLOAD => "SLOAD", SSTORE => "SSTORE",
        JUMP => "JUMP", JUMPI => "JUMPI", PC => "PC", MSIZE => "MSIZE",
        GAS => "GAS", JUMPDEST => "JUMPDEST", PUSH0 => "PUSH0",
        0x60..=0x7f => "PUSHn",
        0x80..=0x8f => "DUPn",
        0x90..=0x9f => "SWAPn",
        0xa0..=0xa4 => "LOGn",
        CREATE => "CREATE", CALL => "CALL", CALLCODE => "CALLCODE",
        RETURN => "RETURN", DELEGATECALL => "DELEGATECALL",
        CREATE2 => "CREATE2", STATICCALL => "STATICCALL",
        REVERT => "REVERT", INVALID => "INVALID",
        SELFDESTRUCT => "SELFDESTRUCT",
        _ => "UNKNOWN",
    }
}
