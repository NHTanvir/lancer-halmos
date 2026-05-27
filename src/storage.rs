//! Symbolic storage model.
//!
//! Storage is modelled as a map from slot (U256) to value (Expr).
//! Symbolic slots are supported via a list of (slot_expr, value_expr) overrides.
//!
//! For keccak-based slot computation (Solidity mappings), we track keccak
//! preimage pairs and enforce injectivity.

use primitive_types::U256;
use std::collections::HashMap;
use crate::symbolic::Expr;
use crate::types::keccak256;

#[derive(Debug, Clone)]
pub struct Storage {
    /// Concrete slot → concrete/symbolic value
    concrete_slots: HashMap<U256, Expr>,
    /// Symbolic slot overrides (slot_expr, value_expr)
    symbolic_slots: Vec<(Expr, Expr)>,
    /// Keccak preimage tracking: hash_value → preimage bytes
    keccak_cache: HashMap<U256, Vec<u8>>,
    /// Whether this storage is "fully symbolic" (svm.enableSymbolicStorage)
    pub fully_symbolic: bool,
    /// Symbolic variable name prefix for fully-symbolic storage
    sym_prefix: String,
}

impl Storage {
    pub fn new(sym_prefix: &str) -> Self {
        Self {
            concrete_slots: HashMap::new(),
            symbolic_slots: Vec::new(),
            keccak_cache: HashMap::new(),
            fully_symbolic: false,
            sym_prefix: sym_prefix.to_string(),
        }
    }

    pub fn enable_symbolic(&mut self) {
        self.fully_symbolic = true;
    }

    /// SLOAD: read from slot
    pub fn load(&self, slot: &Expr) -> Expr {
        match slot {
            Expr::Concrete(s) => {
                if let Some(val) = self.concrete_slots.get(s) {
                    return val.clone();
                }
                if self.fully_symbolic {
                    // Return a fresh symbolic variable for this slot
                    let var = format!("{}_slot_{}", self.sym_prefix,
                        hex::encode(&{let mut b=[0u8;32]; s.to_big_endian(&mut b); b}));
                    return Expr::Var(var);
                }
                Expr::Concrete(U256::zero())
            }
            sym_slot => {
                // Check concrete overrides first
                // Then check symbolic overrides
                for (s, v) in &self.symbolic_slots {
                    if s == sym_slot {
                        return v.clone();
                    }
                }
                if self.fully_symbolic {
                    return Expr::Var(format!("{}_dyn", self.sym_prefix));
                }
                Expr::StoreRead(Box::new(sym_slot.clone()), Box::new(Expr::Concrete(U256::zero())))
            }
        }
    }

    /// SSTORE: write to slot
    pub fn store(&mut self, slot: Expr, value: Expr) {
        match &slot {
            Expr::Concrete(s) => {
                self.concrete_slots.insert(*s, value);
            }
            sym_slot => {
                // Update or add symbolic slot
                for (s, v) in &mut self.symbolic_slots {
                    if s == sym_slot {
                        *v = value;
                        return;
                    }
                }
                self.symbolic_slots.push((slot, value));
            }
        }
    }

    /// Record a keccak preimage (for injectivity tracking)
    pub fn record_keccak(&mut self, preimage: Vec<u8>) -> U256 {
        let hash_bytes = keccak256(&preimage);
        let hash_val = U256::from_big_endian(&hash_bytes);
        self.keccak_cache.insert(hash_val, preimage);
        hash_val
    }

    /// Get preimage for a known hash (for constraint generation)
    pub fn get_keccak_preimage(&self, hash: &U256) -> Option<&Vec<u8>> {
        self.keccak_cache.get(hash)
    }

    /// Snapshot (for invariant testing)
    pub fn snapshot(&self) -> StorageSnapshot {
        StorageSnapshot {
            concrete_slots: self.concrete_slots.clone(),
        }
    }

    /// Restore from snapshot
    pub fn restore(&mut self, snap: &StorageSnapshot) {
        self.concrete_slots = snap.concrete_slots.clone();
        self.symbolic_slots.clear();
    }

    /// Solidity mapping slot: keccak256(key . base_slot)
    pub fn mapping_slot(key: &[u8; 32], base_slot: &[u8; 32]) -> U256 {
        let mut preimage = vec![0u8; 64];
        preimage[..32].copy_from_slice(key);
        preimage[32..].copy_from_slice(base_slot);
        let hash = keccak256(&preimage);
        U256::from_big_endian(&hash)
    }

    /// Solidity dynamic array element slot: keccak256(base_slot) + index
    pub fn array_element_slot(base_slot: U256, index: U256) -> U256 {
        let mut b = [0u8; 32];
        base_slot.to_big_endian(&mut b);
        let hash_bytes = keccak256(&b);
        let hash = U256::from_big_endian(&hash_bytes);
        hash.overflowing_add(index).0
    }
}

#[derive(Debug, Clone)]
pub struct StorageSnapshot {
    pub concrete_slots: HashMap<U256, Expr>,
}

/// Global state for all contracts (address → Storage)
#[derive(Debug, Clone, Default)]
pub struct WorldState {
    pub storage: HashMap<[u8; 20], Storage>,
    pub balances: HashMap<[u8; 20], Expr>,
    pub codes: HashMap<[u8; 20], Vec<u8>>,
}

impl WorldState {
    pub fn new() -> Self { Self::default() }

    pub fn get_storage_mut(&mut self, addr: &[u8; 20]) -> &mut Storage {
        self.storage.entry(*addr).or_insert_with(|| {
            let prefix = hex::encode(addr);
            Storage::new(&prefix)
        })
    }

    pub fn get_storage(&self, addr: &[u8; 20]) -> Option<&Storage> {
        self.storage.get(addr)
    }

    pub fn get_balance(&self, addr: &[u8; 20]) -> Expr {
        self.balances.get(addr).cloned()
            .unwrap_or(Expr::Concrete(U256::zero()))
    }

    pub fn set_balance(&mut self, addr: [u8; 20], val: Expr) {
        self.balances.insert(addr, val);
    }

    pub fn get_code(&self, addr: &[u8; 20]) -> &[u8] {
        self.codes.get(addr).map(|c| c.as_slice()).unwrap_or(&[])
    }

    pub fn deploy_code(&mut self, addr: [u8; 20], code: Vec<u8>) {
        self.codes.insert(addr, code);
    }
}
