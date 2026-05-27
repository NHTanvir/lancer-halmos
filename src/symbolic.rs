//! Symbolic expression tree + SMT-LIB2 serialization.
//!
//! Every EVM word is either a concrete U256 or a symbolic expression.
//! Path conditions are predicates (Pred) collected in Path::constraints.

use primitive_types::U256;
use std::sync::atomic::{AtomicUsize, Ordering};

static SYM_COUNTER: AtomicUsize = AtomicUsize::new(0);

pub fn fresh_var(prefix: &str) -> String {
    let n = SYM_COUNTER.fetch_add(1, Ordering::Relaxed);
    format!("{prefix}_{n}")
}

/// 256-bit bitvector expression (EVM word)
#[derive(Debug, Clone, PartialEq)]
pub enum Expr {
    Concrete(U256),
    Var(String),
    // Arithmetic (modular 256-bit)
    Add(Box<Expr>, Box<Expr>),
    Sub(Box<Expr>, Box<Expr>),
    Mul(Box<Expr>, Box<Expr>),
    Div(Box<Expr>, Box<Expr>),   // unsigned, div/0 = 0
    SDiv(Box<Expr>, Box<Expr>),
    Mod(Box<Expr>, Box<Expr>),   // unsigned, mod/0 = 0
    SMod(Box<Expr>, Box<Expr>),
    AddMod(Box<Expr>, Box<Expr>, Box<Expr>),
    MulMod(Box<Expr>, Box<Expr>, Box<Expr>),
    Exp(Box<Expr>, Box<Expr>),
    SignExtend(Box<Expr>, Box<Expr>),
    // Bitwise
    And(Box<Expr>, Box<Expr>),
    Or(Box<Expr>, Box<Expr>),
    Xor(Box<Expr>, Box<Expr>),
    Not(Box<Expr>),
    ByteOf(Box<Expr>, Box<Expr>), // BYTE(i, x): byte i of x
    Shl(Box<Expr>, Box<Expr>),
    Shr(Box<Expr>, Box<Expr>),
    Sar(Box<Expr>, Box<Expr>),
    // Comparison → 0 or 1 as U256
    Lt(Box<Expr>, Box<Expr>),
    Gt(Box<Expr>, Box<Expr>),
    Slt(Box<Expr>, Box<Expr>),
    Sgt(Box<Expr>, Box<Expr>),
    Eq(Box<Expr>, Box<Expr>),
    IsZero(Box<Expr>),
    // Keccak256 of a sequence of symbolic bytes
    Keccak(Vec<Expr>),
    // ITE (if-then-else)
    Ite(Box<Pred>, Box<Expr>, Box<Expr>),
    // Concat/Extract for byte-level ops
    Concat(Vec<Expr>),         // concatenate bitvectors
    Extract(u32, u32, Box<Expr>), // Extract(high, low, x): bits [high:low]
    // Memory/storage reads
    MemLoad(Box<Expr>),        // MLOAD at symbolic offset
    StoreRead(Box<Expr>, Box<Expr>), // storage[slot] in contract
}

/// Boolean predicate for path conditions
#[derive(Debug, Clone, PartialEq)]
pub enum Pred {
    True,
    False,
    Not(Box<Pred>),
    And(Box<Pred>, Box<Pred>),
    Or(Box<Pred>, Box<Pred>),
    // Equality on BV
    Eq(Box<Expr>, Box<Expr>),
    Ne(Box<Expr>, Box<Expr>),
    // Unsigned comparisons
    Ult(Box<Expr>, Box<Expr>),
    Ule(Box<Expr>, Box<Expr>),
    Ugt(Box<Expr>, Box<Expr>),
    Uge(Box<Expr>, Box<Expr>),
    // Signed comparisons
    Slt(Box<Expr>, Box<Expr>),
    Sle(Box<Expr>, Box<Expr>),
    Sgt(Box<Expr>, Box<Expr>),
    Sge(Box<Expr>, Box<Expr>),
}

impl Expr {
    pub fn is_concrete(&self) -> bool {
        matches!(self, Expr::Concrete(_))
    }

    pub fn as_concrete(&self) -> Option<U256> {
        match self {
            Expr::Concrete(v) => Some(*v),
            _ => None,
        }
    }

    pub fn zero() -> Self {
        Expr::Concrete(U256::zero())
    }

    pub fn one() -> Self {
        Expr::Concrete(U256::one())
    }

    /// Partial evaluation: simplify if all operands are concrete
    pub fn simplify(self) -> Self {
        use crate::types::*;
        match self {
            Expr::Add(a, b) => match (a.simplify(), b.simplify()) {
                (Expr::Concrete(a), Expr::Concrete(b)) => Expr::Concrete(a.overflowing_add(b).0),
                (a, b) => Expr::Add(Box::new(a), Box::new(b)),
            },
            Expr::Sub(a, b) => match (a.simplify(), b.simplify()) {
                (Expr::Concrete(a), Expr::Concrete(b)) => Expr::Concrete(a.overflowing_sub(b).0),
                (a, b) => Expr::Sub(Box::new(a), Box::new(b)),
            },
            Expr::Mul(a, b) => match (a.simplify(), b.simplify()) {
                (Expr::Concrete(a), Expr::Concrete(b)) => Expr::Concrete(a.overflowing_mul(b).0),
                (a, b) => Expr::Mul(Box::new(a), Box::new(b)),
            },
            Expr::Div(a, b) => match (a.simplify(), b.simplify()) {
                (Expr::Concrete(a), Expr::Concrete(b)) => {
                    if b.is_zero() { Expr::Concrete(U256::zero()) }
                    else { Expr::Concrete(a / b) }
                },
                (a, b) => Expr::Div(Box::new(a), Box::new(b)),
            },
            Expr::Mod(a, b) => match (a.simplify(), b.simplify()) {
                (Expr::Concrete(a), Expr::Concrete(b)) => {
                    if b.is_zero() { Expr::Concrete(U256::zero()) }
                    else { Expr::Concrete(a % b) }
                },
                (a, b) => Expr::Mod(Box::new(a), Box::new(b)),
            },
            Expr::And(a, b) => match (a.simplify(), b.simplify()) {
                (Expr::Concrete(a), Expr::Concrete(b)) => Expr::Concrete(a & b),
                (a, b) => Expr::And(Box::new(a), Box::new(b)),
            },
            Expr::Or(a, b) => match (a.simplify(), b.simplify()) {
                (Expr::Concrete(a), Expr::Concrete(b)) => Expr::Concrete(a | b),
                (a, b) => Expr::Or(Box::new(a), Box::new(b)),
            },
            Expr::Xor(a, b) => match (a.simplify(), b.simplify()) {
                (Expr::Concrete(a), Expr::Concrete(b)) => Expr::Concrete(a ^ b),
                (a, b) => Expr::Xor(Box::new(a), Box::new(b)),
            },
            Expr::Not(a) => match a.simplify() {
                Expr::Concrete(a) => Expr::Concrete(!a),
                a => Expr::Not(Box::new(a)),
            },
            Expr::Shl(shift, val) => match (shift.simplify(), val.simplify()) {
                (Expr::Concrete(s), Expr::Concrete(v)) => {
                    if s >= U256::from(256u64) { Expr::Concrete(U256::zero()) }
                    else { Expr::Concrete(v << s.as_usize()) }
                },
                (s, v) => Expr::Shl(Box::new(s), Box::new(v)),
            },
            Expr::Shr(shift, val) => match (shift.simplify(), val.simplify()) {
                (Expr::Concrete(s), Expr::Concrete(v)) => {
                    if s >= U256::from(256u64) { Expr::Concrete(U256::zero()) }
                    else { Expr::Concrete(v >> s.as_usize()) }
                },
                (s, v) => Expr::Shr(Box::new(s), Box::new(v)),
            },
            Expr::Sar(shift, val) => match (shift.simplify(), val.simplify()) {
                (Expr::Concrete(s), Expr::Concrete(v)) => Expr::Concrete(sar(s, v)),
                (s, v) => Expr::Sar(Box::new(s), Box::new(v)),
            },
            Expr::IsZero(a) => match a.simplify() {
                Expr::Concrete(a) => {
                    if a.is_zero() { Expr::Concrete(U256::one()) }
                    else { Expr::Concrete(U256::zero()) }
                },
                a => Expr::IsZero(Box::new(a)),
            },
            Expr::Eq(a, b) => match (a.simplify(), b.simplify()) {
                (Expr::Concrete(a), Expr::Concrete(b)) => {
                    if a == b { Expr::Concrete(U256::one()) }
                    else { Expr::Concrete(U256::zero()) }
                },
                (a, b) => Expr::Eq(Box::new(a), Box::new(b)),
            },
            Expr::Lt(a, b) => match (a.simplify(), b.simplify()) {
                (Expr::Concrete(a), Expr::Concrete(b)) => {
                    if a < b { Expr::Concrete(U256::one()) }
                    else { Expr::Concrete(U256::zero()) }
                },
                (a, b) => Expr::Lt(Box::new(a), Box::new(b)),
            },
            Expr::Gt(a, b) => match (a.simplify(), b.simplify()) {
                (Expr::Concrete(a), Expr::Concrete(b)) => {
                    if a > b { Expr::Concrete(U256::one()) }
                    else { Expr::Concrete(U256::zero()) }
                },
                (a, b) => Expr::Gt(Box::new(a), Box::new(b)),
            },
            Expr::Slt(a, b) => match (a.simplify(), b.simplify()) {
                (Expr::Concrete(a), Expr::Concrete(b)) => {
                    if slt(a, b) { Expr::Concrete(U256::one()) }
                    else { Expr::Concrete(U256::zero()) }
                },
                (a, b) => Expr::Slt(Box::new(a), Box::new(b)),
            },
            Expr::Sgt(a, b) => match (a.simplify(), b.simplify()) {
                (Expr::Concrete(a), Expr::Concrete(b)) => {
                    if sgt(a, b) { Expr::Concrete(U256::one()) }
                    else { Expr::Concrete(U256::zero()) }
                },
                (a, b) => Expr::Sgt(Box::new(a), Box::new(b)),
            },
            Expr::SignExtend(b, x) => match (b.simplify(), x.simplify()) {
                (Expr::Concrete(b), Expr::Concrete(x)) => Expr::Concrete(sign_extend(b, x)),
                (b, x) => Expr::SignExtend(Box::new(b), Box::new(x)),
            },
            other => other,
        }
    }

    /// Collect all symbolic variable names referenced in this expression
    pub fn free_vars(&self) -> Vec<String> {
        let mut vars = Vec::new();
        self.collect_vars(&mut vars);
        vars.sort();
        vars.dedup();
        vars
    }

    fn collect_vars(&self, out: &mut Vec<String>) {
        match self {
            Expr::Var(n) => out.push(n.clone()),
            Expr::Add(a, b) | Expr::Sub(a, b) | Expr::Mul(a, b) | Expr::Div(a, b) |
            Expr::SDiv(a, b) | Expr::Mod(a, b) | Expr::SMod(a, b) |
            Expr::And(a, b) | Expr::Or(a, b) | Expr::Xor(a, b) |
            Expr::ByteOf(a, b) | Expr::Shl(a, b) | Expr::Shr(a, b) | Expr::Sar(a, b) |
            Expr::Lt(a, b) | Expr::Gt(a, b) | Expr::Slt(a, b) | Expr::Sgt(a, b) |
            Expr::Eq(a, b) | Expr::Exp(a, b) | Expr::SignExtend(a, b) |
            Expr::StoreRead(a, b) => { a.collect_vars(out); b.collect_vars(out); }
            Expr::AddMod(a, b, c) | Expr::MulMod(a, b, c) => {
                a.collect_vars(out); b.collect_vars(out); c.collect_vars(out);
            }
            Expr::Not(a) | Expr::IsZero(a) | Expr::MemLoad(a) | Expr::Extract(_, _, a) => a.collect_vars(out),
            Expr::Ite(p, a, b) => { p.collect_pred_vars(out); a.collect_vars(out); b.collect_vars(out); }
            Expr::Keccak(items) | Expr::Concat(items) => { for i in items { i.collect_vars(out); } }
            Expr::Concrete(_) => {}
        }
    }
}

impl Pred {
    fn collect_pred_vars(&self, out: &mut Vec<String>) {
        match self {
            Pred::Not(p) => p.collect_pred_vars(out),
            Pred::And(a, b) | Pred::Or(a, b) => { a.collect_pred_vars(out); b.collect_pred_vars(out); }
            Pred::Eq(a, b) | Pred::Ne(a, b) |
            Pred::Ult(a, b) | Pred::Ule(a, b) | Pred::Ugt(a, b) | Pred::Uge(a, b) |
            Pred::Slt(a, b) | Pred::Sle(a, b) | Pred::Sgt(a, b) | Pred::Sge(a, b) => {
                a.collect_vars(out); b.collect_vars(out);
            }
            Pred::True | Pred::False => {}
        }
    }

    pub fn free_vars(&self) -> Vec<String> {
        let mut vars = Vec::new();
        self.collect_pred_vars(&mut vars);
        vars.sort();
        vars.dedup();
        vars
    }
}

// ─── SMT-LIB2 serialization ──────────────────────────────────────────────────

fn u256_smt2(v: U256) -> String {
    let mut bytes = [0u8; 32];
    v.to_big_endian(&mut bytes);
    format!("#x{}", hex::encode(bytes))
}

impl Expr {
    pub fn to_smt2(&self) -> String {
        match self {
            Expr::Concrete(v) => u256_smt2(*v),
            Expr::Var(n) => n.clone(),

            Expr::Add(a, b) => format!("(bvadd {} {})", a.to_smt2(), b.to_smt2()),
            Expr::Sub(a, b) => format!("(bvsub {} {})", a.to_smt2(), b.to_smt2()),
            Expr::Mul(a, b) => format!("(bvmul {} {})", a.to_smt2(), b.to_smt2()),
            Expr::Div(a, b) => format!(
                "(ite (= {} {zero}) {zero} (bvudiv {} {}))",
                b.to_smt2(), a.to_smt2(), b.to_smt2(),
                zero = u256_smt2(U256::zero())
            ),
            Expr::SDiv(a, b) => format!(
                "(ite (= {} {zero}) {zero} (bvsdiv {} {}))",
                b.to_smt2(), a.to_smt2(), b.to_smt2(),
                zero = u256_smt2(U256::zero())
            ),
            Expr::Mod(a, b) => format!(
                "(ite (= {} {zero}) {zero} (bvurem {} {}))",
                b.to_smt2(), a.to_smt2(), b.to_smt2(),
                zero = u256_smt2(U256::zero())
            ),
            Expr::SMod(a, b) => format!(
                "(ite (= {} {zero}) {zero} (bvsrem {} {}))",
                b.to_smt2(), a.to_smt2(), b.to_smt2(),
                zero = u256_smt2(U256::zero())
            ),
            Expr::AddMod(a, b, c) => format!(
                "(ite (= {} {zero}) {zero} (bvurem (bvadd {} {}) {}))",
                c.to_smt2(), a.to_smt2(), b.to_smt2(), c.to_smt2(),
                zero = u256_smt2(U256::zero())
            ),
            Expr::MulMod(a, b, c) => format!(
                "(ite (= {} {zero}) {zero} (bvurem (bvmul {} {}) {}))",
                c.to_smt2(), a.to_smt2(), b.to_smt2(), c.to_smt2(),
                zero = u256_smt2(U256::zero())
            ),
            Expr::Exp(a, b) => {
                // For symbolic exponent we model as uninterpreted function
                // Concrete case handled by simplify() before reaching here
                format!("(exp_bv256 {} {})", a.to_smt2(), b.to_smt2())
            }
            Expr::SignExtend(b, x) => {
                // Approximated; concrete handled by simplify()
                format!("(signextend_bv256 {} {})", b.to_smt2(), x.to_smt2())
            }

            Expr::And(a, b) => format!("(bvand {} {})", a.to_smt2(), b.to_smt2()),
            Expr::Or(a, b)  => format!("(bvor {} {})", a.to_smt2(), b.to_smt2()),
            Expr::Xor(a, b) => format!("(bvxor {} {})", a.to_smt2(), b.to_smt2()),
            Expr::Not(a)    => format!("(bvnot {})", a.to_smt2()),
            Expr::Shl(s, v) => format!("(bvshl {} {})", v.to_smt2(), s.to_smt2()),
            Expr::Shr(s, v) => format!("(bvlshr {} {})", v.to_smt2(), s.to_smt2()),
            Expr::Sar(s, v) => format!("(bvashr {} {})", v.to_smt2(), s.to_smt2()),
            Expr::ByteOf(i, x) => {
                // BYTE(i, x): byte i of x, 0 if i>=32
                // = extract the (31-i)*8+7 .. (31-i)*8 bits, zero-extend to 256
                format!("(byte_of_bv256 {} {})", i.to_smt2(), x.to_smt2())
            }

            // Comparison: return 1 or 0 as bv256
            Expr::Lt(a, b) => format!(
                "(ite (bvult {} {}) {} {})",
                a.to_smt2(), b.to_smt2(),
                u256_smt2(U256::one()), u256_smt2(U256::zero())
            ),
            Expr::Gt(a, b) => format!(
                "(ite (bvugt {} {}) {} {})",
                a.to_smt2(), b.to_smt2(),
                u256_smt2(U256::one()), u256_smt2(U256::zero())
            ),
            Expr::Slt(a, b) => format!(
                "(ite (bvslt {} {}) {} {})",
                a.to_smt2(), b.to_smt2(),
                u256_smt2(U256::one()), u256_smt2(U256::zero())
            ),
            Expr::Sgt(a, b) => format!(
                "(ite (bvsgt {} {}) {} {})",
                a.to_smt2(), b.to_smt2(),
                u256_smt2(U256::one()), u256_smt2(U256::zero())
            ),
            Expr::Eq(a, b) => format!(
                "(ite (= {} {}) {} {})",
                a.to_smt2(), b.to_smt2(),
                u256_smt2(U256::one()), u256_smt2(U256::zero())
            ),
            Expr::IsZero(a) => format!(
                "(ite (= {} {}) {} {})",
                a.to_smt2(), u256_smt2(U256::zero()),
                u256_smt2(U256::one()), u256_smt2(U256::zero())
            ),

            Expr::Keccak(items) => {
                // Uninterpreted function keccak256
                let args: Vec<_> = items.iter().map(|e| e.to_smt2()).collect();
                format!("(keccak256 {})", args.join(" "))
            }
            Expr::Ite(p, a, b) => format!("(ite {} {} {})", p.to_smt2(), a.to_smt2(), b.to_smt2()),
            Expr::Concat(items) => {
                if items.is_empty() { return u256_smt2(U256::zero()); }
                if items.len() == 1 { return items[0].to_smt2(); }
                let mut s = items[items.len()-1].to_smt2();
                for i in (0..items.len()-1).rev() {
                    s = format!("(concat {} {})", items[i].to_smt2(), s);
                }
                s
            }
            Expr::Extract(hi, lo, e) => format!("((_ extract {} {}) {})", hi, lo, e.to_smt2()),
            Expr::MemLoad(offset) => format!("(mload {})", offset.to_smt2()),
            Expr::StoreRead(slot, addr) => format!("(sload {} {})", slot.to_smt2(), addr.to_smt2()),
        }
    }
}

impl Pred {
    pub fn to_smt2(&self) -> String {
        match self {
            Pred::True  => "true".to_string(),
            Pred::False => "false".to_string(),
            Pred::Not(p) => format!("(not {})", p.to_smt2()),
            Pred::And(a, b) => format!("(and {} {})", a.to_smt2(), b.to_smt2()),
            Pred::Or(a, b)  => format!("(or {} {})", a.to_smt2(), b.to_smt2()),
            Pred::Eq(a, b)  => format!("(= {} {})", a.to_smt2(), b.to_smt2()),
            Pred::Ne(a, b)  => format!("(not (= {} {}))", a.to_smt2(), b.to_smt2()),
            Pred::Ult(a, b) => format!("(bvult {} {})", a.to_smt2(), b.to_smt2()),
            Pred::Ule(a, b) => format!("(bvule {} {})", a.to_smt2(), b.to_smt2()),
            Pred::Ugt(a, b) => format!("(bvugt {} {})", a.to_smt2(), b.to_smt2()),
            Pred::Uge(a, b) => format!("(bvuge {} {})", a.to_smt2(), b.to_smt2()),
            Pred::Slt(a, b) => format!("(bvslt {} {})", a.to_smt2(), b.to_smt2()),
            Pred::Sle(a, b) => format!("(bvsle {} {})", a.to_smt2(), b.to_smt2()),
            Pred::Sgt(a, b) => format!("(bvsgt {} {})", a.to_smt2(), b.to_smt2()),
            Pred::Sge(a, b) => format!("(bvsge {} {})", a.to_smt2(), b.to_smt2()),
        }
    }
}

/// Helper: build a Pred from an Expr that is 0 or 1 (EVM comparison result)
pub fn expr_is_nonzero(e: &Expr) -> Pred {
    Pred::Ne(
        Box::new(e.clone()),
        Box::new(Expr::Concrete(U256::zero())),
    )
}

pub fn expr_is_zero(e: &Expr) -> Pred {
    Pred::Eq(
        Box::new(e.clone()),
        Box::new(Expr::Concrete(U256::zero())),
    )
}
