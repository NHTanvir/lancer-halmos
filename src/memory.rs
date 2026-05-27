//! Symbolic byte vector — models EVM memory.
//!
//! EVM memory is byte-addressed. MLOAD reads 32 bytes. MSTORE writes 32 bytes.
//! MSTORE8 writes 1 byte.
//!
//! Memory is modelled as a flat vector of MemByte. Grows lazily on access.

use primitive_types::U256;
use crate::symbolic::Expr;

#[derive(Debug, Clone)]
pub enum MemByte {
    Concrete(u8),
    Symbolic(Box<Expr>),
}

impl MemByte {
    fn zero() -> Self { MemByte::Concrete(0) }
}

#[derive(Debug, Clone, Default)]
pub struct Memory {
    bytes: Vec<MemByte>,
}

impl Memory {
    pub fn new() -> Self { Self::default() }

    fn ensure_capacity(&mut self, offset: usize, len: usize) {
        let end = offset + len;
        if self.bytes.len() < end {
            self.bytes.resize_with(end, MemByte::zero);
        }
    }

    pub fn size(&self) -> usize {
        // Round up to 32-byte boundary per EVM MSIZE semantics
        let n = self.bytes.len();
        (n + 31) / 32 * 32
    }

    /// Write a single concrete byte
    pub fn write_byte(&mut self, offset: usize, val: u8) {
        self.ensure_capacity(offset, 1);
        self.bytes[offset] = MemByte::Concrete(val);
    }

    /// Write 32 bytes (MSTORE) — concrete value
    pub fn write_word(&mut self, offset: usize, val: U256) {
        self.ensure_capacity(offset, 32);
        let mut bytes = [0u8; 32];
        val.to_big_endian(&mut bytes);
        for (i, b) in bytes.iter().enumerate() {
            self.bytes[offset + i] = MemByte::Concrete(*b);
        }
    }

    /// Write 32 bytes — symbolic value (splits into 32 symbolic byte expressions)
    pub fn write_word_symbolic(&mut self, offset: usize, expr: Expr) {
        self.ensure_capacity(offset, 32);
        for i in 0..32u32 {
            let bit_hi = (31 - i) * 8 + 7;
            let bit_lo = (31 - i) * 8;
            let byte_expr = Expr::Extract(bit_hi, bit_lo, Box::new(expr.clone()));
            self.bytes[offset + i as usize] = MemByte::Symbolic(Box::new(byte_expr));
        }
    }

    /// Read 32 bytes (MLOAD).
    /// Returns Concrete if all bytes are concrete, Symbolic (Concat) otherwise.
    pub fn read_word(&mut self, offset: usize) -> Expr {
        self.ensure_capacity(offset, 32);
        let mut all_concrete = true;
        let mut concrete_bytes = [0u8; 32];
        let mut sym_bytes: Vec<Expr> = Vec::with_capacity(32);

        for i in 0..32 {
            match &self.bytes[offset + i] {
                MemByte::Concrete(b) => {
                    concrete_bytes[i] = *b;
                    sym_bytes.push(Expr::Concrete(U256::from(*b as u64)));
                }
                MemByte::Symbolic(e) => {
                    all_concrete = false;
                    sym_bytes.push((**e).clone());
                }
            }
        }

        if all_concrete {
            Expr::Concrete(U256::from_big_endian(&concrete_bytes))
        } else {
            // Concatenate: each element is 8-bit, we need to form a 256-bit value
            // Use zero-extended bytes and shift/or
            let mut result = Expr::zero();
            for (i, byte_expr) in sym_bytes.iter().enumerate() {
                let shift = (31 - i) * 8;
                let shifted = Expr::Shl(
                    Box::new(Expr::Concrete(U256::from(shift as u64))),
                    Box::new(byte_expr.clone()),
                );
                result = Expr::Or(Box::new(result), Box::new(shifted));
            }
            result
        }
    }

    /// Read a slice of concrete bytes (for CALLDATACOPY, CODECOPY etc)
    pub fn read_bytes(&mut self, offset: usize, len: usize) -> Vec<u8> {
        if len == 0 { return vec![]; }
        self.ensure_capacity(offset, len);
        let mut out = vec![0u8; len];
        for i in 0..len {
            match &self.bytes[offset + i] {
                MemByte::Concrete(b) => out[i] = *b,
                MemByte::Symbolic(_) => out[i] = 0, // fallback for concrete reads
            }
        }
        out
    }

    /// Write a concrete byte slice into memory
    pub fn write_bytes(&mut self, offset: usize, data: &[u8]) {
        self.ensure_capacity(offset, data.len());
        for (i, b) in data.iter().enumerate() {
            self.bytes[offset + i] = MemByte::Concrete(*b);
        }
    }

    /// Check whether a range is entirely concrete
    pub fn range_is_concrete(&self, offset: usize, len: usize) -> bool {
        if offset + len > self.bytes.len() { return true; } // zero-padded
        self.bytes[offset..offset+len].iter().all(|b| matches!(b, MemByte::Concrete(_)))
    }

    /// Get concrete bytes for hashing (keccak256 of memory range)
    pub fn get_concrete_or_zero(&self, offset: usize, len: usize) -> Vec<u8> {
        let mut out = vec![0u8; len];
        let available = self.bytes.len().saturating_sub(offset);
        let fill = available.min(len);
        for i in 0..fill {
            if let MemByte::Concrete(b) = &self.bytes[offset + i] {
                out[i] = *b;
            }
        }
        out
    }

    /// Returns true if any byte in range is symbolic
    pub fn range_has_symbolic(&self, offset: usize, len: usize) -> bool {
        if offset + len > self.bytes.len() { return false; }
        self.bytes[offset..offset+len].iter().any(|b| matches!(b, MemByte::Symbolic(_)))
    }
}
