use primitive_types::U256;

pub type Word = U256;
pub type B256 = [u8; 32];
pub type Address = [u8; 20];

pub const ZERO: U256 = U256::zero();
pub const ONE: U256 = U256::one();

/// EVM word size in bytes
pub const WORD_SIZE: usize = 32;

pub fn u256_from_bytes32(b: &[u8; 32]) -> U256 {
    U256::from_big_endian(b)
}

pub fn bytes32_from_u256(v: U256) -> [u8; 32] {
    let mut out = [0u8; 32];
    v.to_big_endian(&mut out);
    out
}

pub fn u256_from_address(addr: &[u8; 20]) -> U256 {
    let mut b = [0u8; 32];
    b[12..32].copy_from_slice(addr);
    U256::from_big_endian(&b)
}

pub fn address_from_u256(v: U256) -> [u8; 20] {
    let mut b = [0u8; 32];
    v.to_big_endian(&mut b);
    let mut addr = [0u8; 20];
    addr.copy_from_slice(&b[12..32]);
    addr
}

/// Keccak256 of data
pub fn keccak256(data: &[u8]) -> B256 {
    use sha3::{Digest, Keccak256};
    let mut h = Keccak256::new();
    h.update(data);
    h.finalize().into()
}

/// Sign-extend a U256 value with `b` byte size (EVM SIGNEXTEND)
pub fn sign_extend(b: U256, x: U256) -> U256 {
    if b >= U256::from(31u64) {
        return x;
    }
    let byte_num = b.as_usize();
    let bit_index = byte_num * 8 + 7;
    let sign_bit_mask = U256::one() << bit_index;
    let mask = sign_bit_mask - U256::one();
    if x & sign_bit_mask != U256::zero() {
        x | !mask
    } else {
        x & mask
    }
}

/// EVM signed division
pub fn sdiv(a: U256, b: U256) -> U256 {
    if b.is_zero() {
        return U256::zero();
    }
    let min_int = U256::one() << 255;
    if a == min_int && b == U256::MAX {
        return min_int;
    }
    let (neg_a, abs_a) = if a >= min_int {
        (true, (!a).overflowing_add(U256::one()).0)
    } else {
        (false, a)
    };
    let (neg_b, abs_b) = if b >= min_int {
        (true, (!b).overflowing_add(U256::one()).0)
    } else {
        (false, b)
    };
    let result = abs_a / abs_b;
    if neg_a != neg_b && !result.is_zero() {
        (!result).overflowing_add(U256::one()).0
    } else {
        result
    }
}

/// EVM signed modulo
pub fn smod(a: U256, b: U256) -> U256 {
    if b.is_zero() {
        return U256::zero();
    }
    let min_int = U256::one() << 255;
    let (neg_a, abs_a) = if a >= min_int {
        (true, (!a).overflowing_add(U256::one()).0)
    } else {
        (false, a)
    };
    let (_, abs_b) = if b >= min_int {
        (true, (!b).overflowing_add(U256::one()).0)
    } else {
        (false, b)
    };
    let result = abs_a % abs_b;
    if neg_a && !result.is_zero() {
        (!result).overflowing_add(U256::one()).0
    } else {
        result
    }
}

/// EVM SAR — arithmetic right shift
pub fn sar(shift: U256, val: U256) -> U256 {
    let min_int = U256::one() << 255;
    if shift >= U256::from(256u64) {
        if val >= min_int {
            U256::MAX
        } else {
            U256::zero()
        }
    } else {
        let s = shift.as_usize();
        let shifted = val >> s;
        if val >= min_int {
            let mask = U256::MAX << (256 - s);
            shifted | mask
        } else {
            shifted
        }
    }
}

/// EVM SLT — signed less-than
pub fn slt(a: U256, b: U256) -> bool {
    let min_int = U256::one() << 255;
    match (a >= min_int, b >= min_int) {
        (true, false) => true,   // a negative, b positive
        (false, true) => false,  // a positive, b negative
        _ => a < b,
    }
}

/// EVM SGT — signed greater-than
pub fn sgt(a: U256, b: U256) -> bool {
    slt(b, a)
}
