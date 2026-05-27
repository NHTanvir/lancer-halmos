//! Symbolic EVM — opcode dispatch and path exploration.

use primitive_types::U256;

use crate::config::Config;
use crate::exceptions::{EvmError, HaltReason, StepResult};
use crate::opcodes::*;
use crate::solver::{SatResult, Solver};
use crate::state::{BlockCtx, Frame, FrameResult, Log, Message};
use crate::symbolic::{expr_is_nonzero, expr_is_zero, fresh_var, Expr, Pred};
use crate::types::*;
use crate::cheatcodes::CHEATCODE_ADDR;

// ── Macros (must be defined before use in Rust) ───────────────────────────────

macro_rules! pop {
    ($frame:expr) => {
        match $frame.evm.stack.pop() {
            Ok(v) => v,
            Err(e) => return StepResult::Error(e),
        }
    };
}

macro_rules! push {
    ($frame:expr, $val:expr) => {{
        $frame.evm.pc += 1;
        match $frame.evm.stack.push($val) {
            Ok(()) => StepResult::Continue,
            Err(e) => StepResult::Error(e),
        }
    }};
}

pub struct SEVM<'a> {
    pub config: &'a Config,
    pub solver: &'a Solver,
}

impl<'a> SEVM<'a> {
    pub fn new(config: &'a Config, solver: &'a Solver) -> Self {
        Self { config, solver }
    }

    /// Execute a frame, returning all terminal frames.
    pub fn run(&self, initial: Frame) -> Vec<Frame> {
        let mut worklist: Vec<Frame> = vec![initial];
        let mut completed: Vec<Frame> = Vec::new();

        while let Some(mut frame) = worklist.pop() {
            loop {
                if frame.evm.pc >= frame.code.len() {
                    frame.result = Some(FrameResult {
                        halt: HaltReason::Stop,
                        return_data: vec![],
                        success: true,
                    });
                    completed.push(frame);
                    break;
                }

                match self.step(&mut frame) {
                    StepResult::Continue => {
                        if frame.evm.stopped {
                            completed.push(frame);
                            break;
                        }
                    }
                    StepResult::Fork(forks) => {
                        for f in forks {
                            worklist.push(f);
                        }
                        break;
                    }
                    StepResult::Halt(h) => {
                        let return_data = match &h {
                            HaltReason::Return(d) | HaltReason::Revert(d) => d.clone(),
                            _ => vec![],
                        };
                        let success = matches!(h, HaltReason::Return(_) | HaltReason::Stop);
                        frame.result = Some(FrameResult { halt: h, return_data, success });
                        completed.push(frame);
                        break;
                    }
                    StepResult::Error(e) => {
                        frame.result = Some(FrameResult {
                            halt: HaltReason::Revert(vec![]),
                            return_data: vec![],
                            success: false,
                        });
                        tracing::debug!("EVM error at pc={}: {}", frame.evm.pc, e);
                        completed.push(frame);
                        break;
                    }
                }
            }
        }

        completed
    }

    fn step(&self, frame: &mut Frame) -> StepResult {
        let opcode = frame.code[frame.evm.pc];

        if self.config.depth > 0 && frame.path.steps > self.config.depth {
            return StepResult::Error(EvmError::PathDepthExceeded);
        }
        frame.path.steps += 1;

        match opcode {
            STOP => {
                frame.evm.stopped = true;
                StepResult::Halt(HaltReason::Stop)
            }

            // ── Arithmetic ────────────────────────────────────────────────────
            ADD => self.binop(frame, |a, b| match (a.as_concrete(), b.as_concrete()) {
                (Some(av), Some(bv)) => Expr::Concrete(av.overflowing_add(bv).0),
                _ => Expr::Add(Box::new(a), Box::new(b)),
            }),
            MUL => self.binop(frame, |a, b| match (a.as_concrete(), b.as_concrete()) {
                (Some(av), Some(bv)) => Expr::Concrete(av.overflowing_mul(bv).0),
                _ => Expr::Mul(Box::new(a), Box::new(b)),
            }),
            SUB => self.binop(frame, |a, b| match (a.as_concrete(), b.as_concrete()) {
                (Some(av), Some(bv)) => Expr::Concrete(av.overflowing_sub(bv).0),
                _ => Expr::Sub(Box::new(a), Box::new(b)),
            }),
            DIV => self.binop(frame, |a, b| match (a.as_concrete(), b.as_concrete()) {
                (Some(av), Some(bv)) => {
                    if bv.is_zero() { Expr::Concrete(U256::zero()) }
                    else { Expr::Concrete(av / bv) }
                }
                _ => Expr::Div(Box::new(a), Box::new(b)),
            }),
            SDIV => self.binop(frame, |a, b| match (a.as_concrete(), b.as_concrete()) {
                (Some(av), Some(bv)) => Expr::Concrete(sdiv(av, bv)),
                _ => Expr::SDiv(Box::new(a), Box::new(b)),
            }),
            MOD => self.binop(frame, |a, b| match (a.as_concrete(), b.as_concrete()) {
                (Some(av), Some(bv)) => {
                    if bv.is_zero() { Expr::Concrete(U256::zero()) }
                    else { Expr::Concrete(av % bv) }
                }
                _ => Expr::Mod(Box::new(a), Box::new(b)),
            }),
            SMOD => self.binop(frame, |a, b| match (a.as_concrete(), b.as_concrete()) {
                (Some(av), Some(bv)) => Expr::Concrete(smod(av, bv)),
                _ => Expr::SMod(Box::new(a), Box::new(b)),
            }),
            ADDMOD => {
                let a = pop!(frame);
                let b = pop!(frame);
                let n = pop!(frame);
                let result = match (a.as_concrete(), b.as_concrete(), n.as_concrete()) {
                    (Some(av), Some(bv), Some(nv)) => {
                        if nv.is_zero() { Expr::Concrete(U256::zero()) }
                        else {
                            let sum = av.overflowing_add(bv).0;
                            Expr::Concrete(sum % nv)
                        }
                    }
                    _ => Expr::AddMod(Box::new(a), Box::new(b), Box::new(n)),
                };
                push!(frame, result)
            }
            MULMOD => {
                let a = pop!(frame);
                let b = pop!(frame);
                let n = pop!(frame);
                let result = match (a.as_concrete(), b.as_concrete(), n.as_concrete()) {
                    (Some(av), Some(bv), Some(nv)) => {
                        if nv.is_zero() { Expr::Concrete(U256::zero()) }
                        else {
                            use num_bigint::BigUint;
                            let to_bytes = |v: U256| -> [u8; 32] { let mut b = [0u8;32]; v.to_big_endian(&mut b); b };
                            let pa = BigUint::from_bytes_be(&to_bytes(av));
                            let pb = BigUint::from_bytes_be(&to_bytes(bv));
                            let pn = BigUint::from_bytes_be(&to_bytes(nv));
                            let r = (pa * pb) % pn;
                            let rb = r.to_bytes_be();
                            let mut padded = [0u8; 32];
                            let off = 32usize.saturating_sub(rb.len());
                            let clen = rb.len().min(32);
                            padded[off..off+clen].copy_from_slice(&rb[rb.len()-clen..]);
                            Expr::Concrete(U256::from_big_endian(&padded))
                        }
                    }
                    _ => Expr::MulMod(Box::new(a), Box::new(b), Box::new(n)),
                };
                push!(frame, result)
            }
            EXP => {
                let base = pop!(frame);
                let exp = pop!(frame);
                let result = match (base.as_concrete(), exp.as_concrete()) {
                    (Some(bv), Some(ev)) => Expr::Concrete(concrete_exp(bv, ev)),
                    (_, Some(ev)) if ev < U256::from(self.config.smt_exp_by_const as u64) => {
                        let n = ev.as_usize();
                        let mut result = Expr::Concrete(U256::one());
                        for _ in 0..n {
                            result = Expr::Mul(Box::new(result), Box::new(base.clone()));
                        }
                        result
                    }
                    _ => Expr::Exp(Box::new(base), Box::new(exp)),
                };
                push!(frame, result)
            }
            SIGNEXTEND => self.binop(frame, |b, x| match (b.as_concrete(), x.as_concrete()) {
                (Some(bv), Some(xv)) => Expr::Concrete(sign_extend(bv, xv)),
                _ => Expr::SignExtend(Box::new(b), Box::new(x)),
            }),

            // ── Comparison ────────────────────────────────────────────────────
            LT => self.binop(frame, |a, b| match (a.as_concrete(), b.as_concrete()) {
                (Some(av), Some(bv)) => Expr::Concrete(if av < bv { U256::one() } else { U256::zero() }),
                _ => Expr::Lt(Box::new(a), Box::new(b)),
            }),
            GT => self.binop(frame, |a, b| match (a.as_concrete(), b.as_concrete()) {
                (Some(av), Some(bv)) => Expr::Concrete(if av > bv { U256::one() } else { U256::zero() }),
                _ => Expr::Gt(Box::new(a), Box::new(b)),
            }),
            SLT => self.binop(frame, |a, b| match (a.as_concrete(), b.as_concrete()) {
                (Some(av), Some(bv)) => Expr::Concrete(if slt(av, bv) { U256::one() } else { U256::zero() }),
                _ => Expr::Slt(Box::new(a), Box::new(b)),
            }),
            SGT => self.binop(frame, |a, b| match (a.as_concrete(), b.as_concrete()) {
                (Some(av), Some(bv)) => Expr::Concrete(if sgt(av, bv) { U256::one() } else { U256::zero() }),
                _ => Expr::Sgt(Box::new(a), Box::new(b)),
            }),
            EQ => self.binop(frame, |a, b| match (a.as_concrete(), b.as_concrete()) {
                (Some(av), Some(bv)) => Expr::Concrete(if av == bv { U256::one() } else { U256::zero() }),
                _ => Expr::Eq(Box::new(a), Box::new(b)),
            }),
            ISZERO => {
                let a = pop!(frame);
                let result = match a.as_concrete() {
                    Some(v) => Expr::Concrete(if v.is_zero() { U256::one() } else { U256::zero() }),
                    None => Expr::IsZero(Box::new(a)),
                };
                push!(frame, result)
            }

            // ── Bitwise ───────────────────────────────────────────────────────
            AND => self.binop(frame, |a, b| match (a.as_concrete(), b.as_concrete()) {
                (Some(av), Some(bv)) => Expr::Concrete(av & bv),
                _ => Expr::And(Box::new(a), Box::new(b)),
            }),
            OR => self.binop(frame, |a, b| match (a.as_concrete(), b.as_concrete()) {
                (Some(av), Some(bv)) => Expr::Concrete(av | bv),
                _ => Expr::Or(Box::new(a), Box::new(b)),
            }),
            XOR => self.binop(frame, |a, b| match (a.as_concrete(), b.as_concrete()) {
                (Some(av), Some(bv)) => Expr::Concrete(av ^ bv),
                _ => Expr::Xor(Box::new(a), Box::new(b)),
            }),
            NOT => {
                let a = pop!(frame);
                let result = match a.as_concrete() {
                    Some(v) => Expr::Concrete(!v),
                    None => Expr::Not(Box::new(a)),
                };
                push!(frame, result)
            }
            BYTE => {
                let i = pop!(frame);
                let x = pop!(frame);
                let result = match (i.as_concrete(), x.as_concrete()) {
                    (Some(iv), Some(xv)) => {
                        if iv >= U256::from(32u64) {
                            Expr::Concrete(U256::zero())
                        } else {
                            let byte_idx = 31 - iv.as_usize();
                            let mut b = [0u8; 32];
                            xv.to_big_endian(&mut b);
                            Expr::Concrete(U256::from(b[byte_idx]))
                        }
                    }
                    _ => Expr::ByteOf(Box::new(i), Box::new(x)),
                };
                push!(frame, result)
            }
            SHL => self.binop(frame, |s, v| match (s.as_concrete(), v.as_concrete()) {
                (Some(sv), Some(vv)) => {
                    if sv >= U256::from(256u64) { Expr::Concrete(U256::zero()) }
                    else { Expr::Concrete(vv << sv.as_usize()) }
                }
                _ => Expr::Shl(Box::new(s), Box::new(v)),
            }),
            SHR => self.binop(frame, |s, v| match (s.as_concrete(), v.as_concrete()) {
                (Some(sv), Some(vv)) => {
                    if sv >= U256::from(256u64) { Expr::Concrete(U256::zero()) }
                    else { Expr::Concrete(vv >> sv.as_usize()) }
                }
                _ => Expr::Shr(Box::new(s), Box::new(v)),
            }),
            SAR => self.binop(frame, |s, v| match (s.as_concrete(), v.as_concrete()) {
                (Some(sv), Some(vv)) => Expr::Concrete(sar(sv, vv)),
                _ => Expr::Sar(Box::new(s), Box::new(v)),
            }),

            // ── SHA3 / Keccak256 ──────────────────────────────────────────────
            KECCAK256 => {
                let offset = pop!(frame);
                let size = pop!(frame);
                let result = match (offset.as_concrete(), size.as_concrete()) {
                    (Some(off), Some(sz)) => {
                        let off_u = off.as_usize();
                        let sz_u = sz.as_usize();
                        if frame.evm.memory.range_is_concrete(off_u, sz_u) {
                            let data = frame.evm.memory.get_concrete_or_zero(off_u, sz_u);
                            let hash_bytes = keccak256(&data);
                            let hash_val = U256::from_big_endian(&hash_bytes);
                            frame.world.get_storage_mut(&frame.msg.callee)
                                .record_keccak(data);
                            Expr::Concrete(hash_val)
                        } else {
                            Expr::Var(fresh_var("keccak"))
                        }
                    }
                    _ => Expr::Var(fresh_var("keccak")),
                };
                push!(frame, result)
            }

            // ── Environment ───────────────────────────────────────────────────
            ADDRESS => push!(frame, Expr::Concrete(u256_from_address(&frame.msg.callee))),
            BALANCE => {
                let addr_expr = pop!(frame);
                let balance = match addr_expr.as_concrete() {
                    Some(v) => frame.world.get_balance(&address_from_u256(v)),
                    None => Expr::Var(fresh_var("balance")),
                };
                push!(frame, balance)
            }
            ORIGIN   => push!(frame, Expr::Concrete(u256_from_address(&frame.msg.origin))),
            CALLER   => push!(frame, Expr::Concrete(u256_from_address(&frame.msg.caller))),
            CALLVALUE => push!(frame, frame.msg.callvalue.clone()),
            CALLDATALOAD => {
                let offset = pop!(frame);
                let result = match offset.as_concrete() {
                    Some(off) => {
                        let off_u = off.as_usize();
                        let word_idx = off_u / 32;
                        if word_idx < frame.msg.calldata_sym.len() {
                            frame.msg.calldata_sym[word_idx].clone()
                        } else if off_u + 32 <= frame.msg.calldata.len() {
                            let mut bytes = [0u8; 32];
                            bytes.copy_from_slice(&frame.msg.calldata[off_u..off_u+32]);
                            Expr::Concrete(U256::from_big_endian(&bytes))
                        } else if off_u < frame.msg.calldata.len() {
                            // Partial read + zero padding
                            let avail = frame.msg.calldata.len() - off_u;
                            let mut bytes = [0u8; 32];
                            bytes[..avail].copy_from_slice(&frame.msg.calldata[off_u..]);
                            Expr::Concrete(U256::from_big_endian(&bytes))
                        } else {
                            Expr::Concrete(U256::zero())
                        }
                    }
                    None => Expr::Var(fresh_var("calldataload")),
                };
                push!(frame, result)
            }
            CALLDATASIZE => {
                if !frame.msg.calldata_sym.is_empty() {
                    push!(frame, Expr::Var(fresh_var("calldatasize")))
                } else {
                    push!(frame, Expr::Concrete(U256::from(frame.msg.calldata.len() as u64)))
                }
            }
            CALLDATACOPY => {
                let dest_off = pop!(frame);
                let src_off = pop!(frame);
                let size = pop!(frame);
                if let (Some(d), Some(s), Some(n)) =
                    (dest_off.as_concrete(), src_off.as_concrete(), size.as_concrete())
                {
                    let d = d.as_usize();
                    let s = s.as_usize();
                    let n = n.as_usize();
                    if n > 0 {
                        let avail = frame.msg.calldata.len().saturating_sub(s);
                        let copy_len = avail.min(n);
                        if copy_len > 0 {
                            let data = frame.msg.calldata[s..s+copy_len].to_vec();
                            frame.evm.memory.write_bytes(d, &data);
                        }
                        if n > copy_len {
                            let zeros = vec![0u8; n - copy_len];
                            frame.evm.memory.write_bytes(d + copy_len, &zeros);
                        }
                    }
                }
                frame.evm.pc += 1;
                StepResult::Continue
            }
            CODESIZE => push!(frame, Expr::Concrete(U256::from(frame.code.len() as u64))),
            CODECOPY => {
                let dest_off = pop!(frame);
                let src_off = pop!(frame);
                let size = pop!(frame);
                if let (Some(d), Some(s), Some(n)) =
                    (dest_off.as_concrete(), src_off.as_concrete(), size.as_concrete())
                {
                    let d = d.as_usize();
                    let s = s.as_usize();
                    let n = n.as_usize();
                    let avail = frame.code.len().saturating_sub(s);
                    let copy_len = avail.min(n);
                    if copy_len > 0 {
                        frame.evm.memory.write_bytes(d, &frame.code[s..s+copy_len]);
                    }
                    if n > copy_len {
                        frame.evm.memory.write_bytes(d + copy_len, &vec![0u8; n - copy_len]);
                    }
                }
                frame.evm.pc += 1;
                StepResult::Continue
            }
            GASPRICE => push!(frame, Expr::Concrete(U256::zero())),
            EXTCODESIZE => {
                let addr_expr = pop!(frame);
                let size = match addr_expr.as_concrete() {
                    Some(v) => {
                        let addr = address_from_u256(v);
                        Expr::Concrete(U256::from(frame.world.get_code(&addr).len() as u64))
                    }
                    None => Expr::Var(fresh_var("extcodesize")),
                };
                push!(frame, size)
            }
            EXTCODECOPY => {
                let _addr = pop!(frame);
                let _dest = pop!(frame);
                let _src = pop!(frame);
                let _len = pop!(frame);
                frame.evm.pc += 1;
                StepResult::Continue
            }
            RETURNDATASIZE => {
                let sz = frame.evm.returndata.len();
                push!(frame, Expr::Concrete(U256::from(sz as u64)))
            }
            RETURNDATACOPY => {
                let dest = pop!(frame);
                let src = pop!(frame);
                let len = pop!(frame);
                if let (Some(d), Some(s), Some(n)) =
                    (dest.as_concrete(), src.as_concrete(), len.as_concrete())
                {
                    let d = d.as_usize();
                    let s = s.as_usize();
                    let n = n.as_usize();
                    if s + n <= frame.evm.returndata.len() {
                        let data = frame.evm.returndata[s..s+n].to_vec();
                        frame.evm.memory.write_bytes(d, &data);
                    }
                }
                frame.evm.pc += 1;
                StepResult::Continue
            }
            EXTCODEHASH => {
                let addr_expr = pop!(frame);
                let hash = match addr_expr.as_concrete() {
                    Some(v) => {
                        let addr = address_from_u256(v);
                        let code = frame.world.get_code(&addr);
                        if code.is_empty() { Expr::Concrete(U256::zero()) }
                        else {
                            let h = keccak256(code);
                            Expr::Concrete(U256::from_big_endian(&h))
                        }
                    }
                    None => Expr::Var(fresh_var("extcodehash")),
                };
                push!(frame, hash)
            }

            // ── Block ──────────────────────────────────────────────────────────
            BLOCKHASH  => { let _n = pop!(frame); push!(frame, Expr::Var(fresh_var("blockhash"))) }
            COINBASE   => push!(frame, Expr::Concrete(u256_from_address(&frame.block.coinbase))),
            TIMESTAMP  => push!(frame, frame.block.timestamp.clone()),
            NUMBER     => push!(frame, frame.block.number.clone()),
            DIFFICULTY => push!(frame, frame.block.difficulty.clone()),
            GASLIMIT   => push!(frame, Expr::Concrete(U256::from(frame.block.gaslimit))),
            CHAINID    => push!(frame, Expr::Concrete(U256::from(frame.block.chainid))),
            SELFBALANCE => push!(frame, frame.world.get_balance(&frame.msg.callee)),
            BASEFEE    => push!(frame, frame.block.basefee.clone()),

            // ── Stack ──────────────────────────────────────────────────────────
            POP => { pop!(frame); frame.evm.pc += 1; StepResult::Continue }

            // ── Memory ─────────────────────────────────────────────────────────
            MLOAD => {
                let offset = pop!(frame);
                let result = match offset.as_concrete() {
                    Some(off) => frame.evm.memory.read_word(off.as_usize()),
                    None => Expr::MemLoad(Box::new(offset)),
                };
                push!(frame, result)
            }
            MSTORE => {
                let offset = pop!(frame);
                let value = pop!(frame);
                match (offset.as_concrete(), value.as_concrete()) {
                    (Some(off), Some(val)) => frame.evm.memory.write_word(off.as_usize(), val),
                    (Some(off), None) => frame.evm.memory.write_word_symbolic(off.as_usize(), value),
                    _ => {}
                }
                frame.evm.pc += 1;
                StepResult::Continue
            }
            MSTORE8 => {
                let offset = pop!(frame);
                let value = pop!(frame);
                if let (Some(off), Some(val)) = (offset.as_concrete(), value.as_concrete()) {
                    let byte = (val & U256::from(0xffu64)).as_usize() as u8;
                    frame.evm.memory.write_byte(off.as_usize(), byte);
                }
                frame.evm.pc += 1;
                StepResult::Continue
            }
            MSIZE => {
                let sz = frame.evm.memory.size();
                push!(frame, Expr::Concrete(U256::from(sz as u64)))
            }

            // ── Storage ────────────────────────────────────────────────────────
            SLOAD => {
                let slot = pop!(frame);
                let val = frame.world.get_storage_mut(&frame.msg.callee).load(&slot);
                push!(frame, val)
            }
            SSTORE => {
                if frame.msg.is_static { return StepResult::Error(EvmError::StaticStateChange); }
                let slot = pop!(frame);
                let value = pop!(frame);
                frame.world.get_storage_mut(&frame.msg.callee).store(slot, value);
                frame.evm.pc += 1;
                StepResult::Continue
            }

            // ── Control flow ───────────────────────────────────────────────────
            JUMP => {
                let dest = pop!(frame);
                match dest.as_concrete() {
                    Some(d) => {
                        let pc = d.as_usize();
                        if pc >= frame.code.len() || frame.code[pc] != JUMPDEST {
                            return StepResult::Error(EvmError::InvalidJump(d));
                        }
                        frame.evm.pc = pc;
                        StepResult::Continue
                    }
                    None => StepResult::Error(EvmError::SymbolicJump),
                }
            }
            JUMPI => {
                let dest = pop!(frame);
                let cond = pop!(frame);
                self.handle_jumpi(frame, dest, cond)
            }
            PC => {
                let pc = frame.evm.pc;
                push!(frame, Expr::Concrete(U256::from(pc as u64)))
            }
            GAS       => push!(frame, Expr::Var(fresh_var("gas"))),
            JUMPDEST  => { frame.evm.pc += 1; StepResult::Continue }

            // ── PUSH ───────────────────────────────────────────────────────────
            PUSH0 => push!(frame, Expr::Concrete(U256::zero())),
            0x60..=0x7f => {
                let n = (opcode - PUSH1 + 1) as usize;
                let start = frame.evm.pc + 1;
                let end = start + n;
                if end > frame.code.len() {
                    return StepResult::Error(EvmError::InvalidOpcode(opcode));
                }
                let mut bytes = [0u8; 32];
                let off = 32 - n;
                bytes[off..32].copy_from_slice(&frame.code[start..end]);
                frame.evm.pc = end;
                match frame.evm.stack.push(Expr::Concrete(U256::from_big_endian(&bytes))) {
                    Ok(()) => StepResult::Continue,
                    Err(e) => StepResult::Error(e),
                }
            }

            // ── DUP ────────────────────────────────────────────────────────────
            0x80..=0x8f => {
                let n = (opcode - DUP1 + 1) as usize;
                match frame.evm.stack.dup(n) {
                    Ok(()) => { frame.evm.pc += 1; StepResult::Continue }
                    Err(e) => StepResult::Error(e),
                }
            }

            // ── SWAP ───────────────────────────────────────────────────────────
            0x90..=0x9f => {
                let n = (opcode - SWAP1 + 1) as usize;
                match frame.evm.stack.swap(n) {
                    Ok(()) => { frame.evm.pc += 1; StepResult::Continue }
                    Err(e) => StepResult::Error(e),
                }
            }

            // ── LOG ────────────────────────────────────────────────────────────
            0xa0..=0xa4 => {
                let n_topics = (opcode - LOG0) as usize;
                let offset = pop!(frame);
                let size = pop!(frame);
                let mut topics = Vec::with_capacity(n_topics);
                for _ in 0..n_topics { topics.push(pop!(frame)); }
                let data = match (offset.as_concrete(), size.as_concrete()) {
                    (Some(off), Some(sz)) => frame.evm.memory.read_bytes(off.as_usize(), sz.as_usize()),
                    _ => vec![],
                };
                frame.logs.push(Log { address: frame.msg.callee, topics, data });
                frame.evm.pc += 1;
                StepResult::Continue
            }

            // ── CREATE / CALL / RETURN / REVERT ──────────────────────────────
            RETURN => {
                let offset = pop!(frame);
                let size = pop!(frame);
                let data = match (offset.as_concrete(), size.as_concrete()) {
                    (Some(off), Some(sz)) => frame.evm.memory.read_bytes(off.as_usize(), sz.as_usize()),
                    _ => vec![],
                };
                StepResult::Halt(HaltReason::Return(data))
            }
            REVERT => {
                let offset = pop!(frame);
                let size = pop!(frame);
                let data = match (offset.as_concrete(), size.as_concrete()) {
                    (Some(off), Some(sz)) => frame.evm.memory.read_bytes(off.as_usize(), sz.as_usize()),
                    _ => vec![],
                };
                StepResult::Halt(HaltReason::Revert(data))
            }
            INVALID     => StepResult::Error(EvmError::InvalidOpcode(0xfe)),
            SELFDESTRUCT => { let _b = pop!(frame); StepResult::Halt(HaltReason::SelfDestruct) }

            CALL | CALLCODE | STATICCALL | DELEGATECALL => self.handle_call(frame, opcode),

            CREATE => {
                let _value = pop!(frame);
                let _offset = pop!(frame);
                let _size = pop!(frame);
                push!(frame, Expr::Var(fresh_var("created")))
            }
            CREATE2 => {
                let _value = pop!(frame);
                let _offset = pop!(frame);
                let _size = pop!(frame);
                let _salt = pop!(frame);
                push!(frame, Expr::Var(fresh_var("created2")))
            }

            unknown => StepResult::Error(EvmError::InvalidOpcode(unknown)),
        }
    }

    /// Helper for binary operations
    fn binop<F>(&self, frame: &mut Frame, op: F) -> StepResult
    where F: FnOnce(Expr, Expr) -> Expr
    {
        let a = match frame.evm.stack.pop() {
            Ok(v) => v, Err(e) => return StepResult::Error(e),
        };
        let b = match frame.evm.stack.pop() {
            Ok(v) => v, Err(e) => return StepResult::Error(e),
        };
        let result = op(a, b);
        frame.evm.pc += 1;
        match frame.evm.stack.push(result) {
            Ok(()) => StepResult::Continue,
            Err(e) => StepResult::Error(e),
        }
    }

    fn handle_jumpi(&self, frame: &mut Frame, dest: Expr, cond: Expr) -> StepResult {
        // Concrete: straightforward
        if let (Some(d), Some(c)) = (dest.as_concrete(), cond.as_concrete()) {
            if c.is_zero() {
                frame.evm.pc += 1;
            } else {
                let pc = d.as_usize();
                if pc >= frame.code.len() || frame.code[pc] != JUMPDEST {
                    return StepResult::Error(EvmError::InvalidJump(d));
                }
                let count = frame.path.record_jump(pc);
                if count > self.config.loop_bound {
                    tracing::warn!("Loop bound exceeded at pc={pc}. Try --loop {}", self.config.loop_bound + 1);
                    return StepResult::Error(EvmError::LoopBound);
                }
                frame.evm.pc = pc;
            }
            return StepResult::Continue;
        }

        // Symbolic condition, concrete destination
        if let Some(d) = dest.as_concrete() {
            let pc_taken = d.as_usize();
            let pc_not_taken = frame.evm.pc + 1;

            if pc_taken >= frame.code.len() || frame.code[pc_taken] != JUMPDEST {
                return StepResult::Error(EvmError::InvalidJump(d));
            }

            let taken_pred = expr_is_nonzero(&cond);
            let not_taken_pred = expr_is_zero(&cond);

            let taken_sat = {
                let mut tp = frame.path.clone();
                tp.add_constraint(taken_pred.clone());
                matches!(self.solver.check_sat(&tp, &[]), SatResult::Sat | SatResult::Unknown)
            };
            let not_taken_sat = {
                let mut tp = frame.path.clone();
                tp.add_constraint(not_taken_pred.clone());
                matches!(self.solver.check_sat(&tp, &[]), SatResult::Sat | SatResult::Unknown)
            };

            match (taken_sat, not_taken_sat) {
                (false, false) => StepResult::Error(EvmError::Infeasible),
                (true, false) => {
                    frame.path.add_constraint(taken_pred);
                    frame.evm.pc = pc_taken;
                    StepResult::Continue
                }
                (false, true) => {
                    frame.path.add_constraint(not_taken_pred);
                    frame.evm.pc = pc_not_taken;
                    StepResult::Continue
                }
                (true, true) => {
                    let mut taken_frame = frame.clone();
                    taken_frame.path.add_constraint(taken_pred);
                    taken_frame.evm.pc = pc_taken;
                    taken_frame.path.record_jump(pc_taken);

                    frame.path.add_constraint(not_taken_pred);
                    frame.evm.pc = pc_not_taken;
                    StepResult::Fork(vec![taken_frame, frame.clone()])
                }
            }
        } else {
            StepResult::Error(EvmError::SymbolicJump)
        }
    }

    fn handle_call(&self, frame: &mut Frame, opcode: u8) -> StepResult {
        let (addr_expr, value, args_off, args_len, ret_off, ret_len) = match opcode {
            CALL | CALLCODE => {
                let _gas = pop!(frame);
                let addr = pop!(frame);
                let value = pop!(frame);
                let aoff = pop!(frame);
                let alen = pop!(frame);
                let roff = pop!(frame);
                let rlen = pop!(frame);
                (addr, value, aoff, alen, roff, rlen)
            }
            _ => { // STATICCALL | DELEGATECALL
                let _gas = pop!(frame);
                let addr = pop!(frame);
                let aoff = pop!(frame);
                let alen = pop!(frame);
                let roff = pop!(frame);
                let rlen = pop!(frame);
                (addr, Expr::Concrete(U256::zero()), aoff, alen, roff, rlen)
            }
        };

        // Cheatcode dispatch
        if let Some(addr_val) = addr_expr.as_concrete() {
            let addr = address_from_u256(addr_val);
            if addr == CHEATCODE_ADDR {
                return self.handle_cheatcode(frame, args_off, args_len, ret_off, ret_len);
            }

            let target_code = frame.world.get_code(&addr).to_vec();
            if !target_code.is_empty() {
                let calldata = match (args_off.as_concrete(), args_len.as_concrete()) {
                    (Some(off), Some(len)) => frame.evm.memory.read_bytes(off.as_usize(), len.as_usize()),
                    _ => vec![],
                };

                let (caller, callee, msg_value) = match opcode {
                    DELEGATECALL => (frame.msg.caller, frame.msg.callee, frame.msg.callvalue.clone()),
                    CALLCODE => (frame.msg.callee, frame.msg.callee, value),
                    _ => (frame.msg.callee, addr, value),
                };

                if frame.msg.depth + 1 > 1024 {
                    push!(frame, Expr::Concrete(U256::zero()));
                    return StepResult::Continue;
                }

                let child_msg = Message {
                    caller,
                    callee,
                    origin: frame.msg.origin,
                    callvalue: msg_value,
                    calldata,
                    calldata_sym: vec![],
                    gas: 21_000_000,
                    is_static: opcode == STATICCALL || frame.msg.is_static,
                    depth: frame.msg.depth + 1,
                };

                let child_frame = Frame::new(target_code, child_msg, frame.world.clone(), frame.block.clone());
                let results = self.run(child_frame);

                if let Some(result_frame) = results.into_iter().next() {
                    if let Some(res) = &result_frame.result {
                        if let (Some(roff), Some(rlen_v)) = (ret_off.as_concrete(), ret_len.as_concrete()) {
                            let copy_len = res.return_data.len().min(rlen_v.as_usize());
                            frame.evm.memory.write_bytes(roff.as_usize(), &res.return_data[..copy_len]);
                        }
                        frame.evm.returndata = res.return_data.clone();
                        frame.world = result_frame.world;
                        let success = if res.success { U256::one() } else { U256::zero() };
                        push!(frame, Expr::Concrete(success));
                        return StepResult::Continue;
                    }
                }
            }
        }

        // Unknown/symbolic target
        push!(frame, Expr::Var(fresh_var("call_success")))
    }

    fn handle_cheatcode(&self, frame: &mut Frame, args_off: Expr, args_len: Expr, ret_off: Expr, ret_len: Expr) -> StepResult {
        use crate::cheatcodes::dispatch_cheatcode;
        let calldata = match (args_off.as_concrete(), args_len.as_concrete()) {
            (Some(off), Some(len)) => frame.evm.memory.read_bytes(off.as_usize(), len.as_usize()),
            _ => vec![],
        };
        match dispatch_cheatcode(frame, &calldata) {
            Ok(ret_data) => {
                if let (Some(roff), Some(rlen)) = (ret_off.as_concrete(), ret_len.as_concrete()) {
                    let copy = ret_data.len().min(rlen.as_usize());
                    if copy > 0 {
                        frame.evm.memory.write_bytes(roff.as_usize(), &ret_data[..copy]);
                    }
                }
                push!(frame, Expr::Concrete(U256::one()))
            }
            Err(e) => StepResult::Error(e),
        }
    }
}

// ── Helpers ───────────────────────────────────────────────────────────────────

/// Concrete EXP: base^exp mod 2^256 (fast exponentiation)
fn concrete_exp(base: U256, exp: U256) -> U256 {
    if exp.is_zero() { return U256::one(); }
    if base.is_zero() { return U256::zero(); }
    let mut result = U256::one();
    let mut b = base;
    let mut e = exp;
    while !e.is_zero() {
        if e & U256::one() != U256::zero() {
            result = result.overflowing_mul(b).0;
        }
        b = b.overflowing_mul(b).0;
        e >>= 1;
    }
    result
}
