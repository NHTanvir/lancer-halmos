//! Symbolic calldata generation.
//! Given an ABI function signature, creates symbolic inputs and encodes
//! them as symbolic calldata that the SEVM can consume.

use primitive_types::U256;
use crate::abi::{AbiFunction, AbiParam, AbiType, encode_word};
use crate::symbolic::{fresh_var, Expr};

/// Symbolic calldata for a function invocation
#[derive(Debug, Clone)]
pub struct SymbolicCalldata {
    /// 4-byte concrete selector
    pub selector: [u8; 4],
    /// Per-word symbolic expressions (each covers 32 bytes of calldata)
    pub sym_words: Vec<Expr>,
    /// Symbolic variables declared (name → bit width)
    pub variables: Vec<(String, u32)>,
    /// Concrete calldata bytes (selector + zeros for dynamic parts)
    pub concrete_prefix: Vec<u8>,
}

impl SymbolicCalldata {
    /// Build symbolic calldata from function ABI
    pub fn from_function(func: &AbiFunction) -> Self {
        let selector = func.selector();
        let mut sym_words: Vec<Expr> = Vec::new();
        let mut variables: Vec<(String, u32)> = Vec::new();

        // Allocate one symbolic word per input parameter (simplified flat layout)
        for param in &func.inputs {
            let words = symbolic_words_for_type(&param.ty, &param.name, &mut variables);
            sym_words.extend(words);
        }

        // Concrete prefix: selector + zeros
        let mut concrete_prefix = vec![0u8; 4 + sym_words.len() * 32];
        concrete_prefix[..4].copy_from_slice(&selector);

        SymbolicCalldata { selector, sym_words, variables, concrete_prefix }
    }

    /// Get the symbolic word at calldata byte offset (after selector)
    pub fn word_at_offset(&self, byte_offset: usize) -> Option<&Expr> {
        if byte_offset % 32 != 0 { return None; }
        let idx = byte_offset / 32;
        self.sym_words.get(idx)
    }
}

/// Generate symbolic expressions for an ABI type
fn symbolic_words_for_type(
    ty: &AbiType,
    name: &str,
    vars: &mut Vec<(String, u32)>,
) -> Vec<Expr> {
    match ty {
        AbiType::Uint(bits) => {
            let var = fresh_var(&format!("arg_{name}"));
            vars.push((var.clone(), *bits));
            let expr = if *bits < 256 {
                // Mask to bit width
                let mask = if *bits == 256 {
                    U256::MAX
                } else {
                    (U256::one() << *bits as usize) - U256::one()
                };
                Expr::And(
                    Box::new(Expr::Var(var)),
                    Box::new(Expr::Concrete(mask)),
                )
            } else {
                Expr::Var(var)
            };
            vec![expr]
        }
        AbiType::Int(bits) => {
            let var = fresh_var(&format!("arg_{name}"));
            vars.push((var.clone(), *bits));
            // Signed: sign-extend from bits
            let expr = Expr::SignExtend(
                Box::new(Expr::Concrete(U256::from((*bits / 8) as u64 - 1))),
                Box::new(Expr::Var(var)),
            );
            vec![expr]
        }
        AbiType::Address => {
            let var = fresh_var(&format!("arg_{name}"));
            vars.push((var.clone(), 160));
            // Mask to 20 bytes
            let mask = (U256::one() << 160) - U256::one();
            vec![Expr::And(Box::new(Expr::Var(var)), Box::new(Expr::Concrete(mask)))]
        }
        AbiType::Bool => {
            let var = fresh_var(&format!("arg_{name}"));
            vars.push((var.clone(), 1));
            // Bool is 0 or 1
            vec![Expr::And(
                Box::new(Expr::Var(var)),
                Box::new(Expr::Concrete(U256::one())),
            )]
        }
        AbiType::BytesN(n) => {
            let var = fresh_var(&format!("arg_{name}"));
            vars.push((var.clone(), (*n as u32) * 8));
            vec![Expr::Var(var)]
        }
        AbiType::Bytes | AbiType::SolString => {
            // Dynamic: emit a symbolic length + symbolic content (simplified to 2 words)
            let len_var = fresh_var(&format!("arg_{name}_len"));
            let data_var = fresh_var(&format!("arg_{name}_data"));
            vars.push((len_var.clone(), 256));
            vars.push((data_var.clone(), 256));
            vec![Expr::Var(len_var), Expr::Var(data_var)]
        }
        AbiType::Array(inner, None) => {
            // Dynamic array: 2 symbolic words (length + one element)
            let len_var = fresh_var(&format!("arg_{name}_len"));
            vars.push((len_var.clone(), 256));
            let mut words = vec![Expr::Var(len_var)];
            let elem_words = symbolic_words_for_type(inner, &format!("{name}_elem"), vars);
            words.extend(elem_words);
            words
        }
        AbiType::Array(inner, Some(n)) => {
            let mut words = Vec::new();
            for i in 0..*n {
                let elem_words = symbolic_words_for_type(inner, &format!("{name}_{i}"), vars);
                words.extend(elem_words);
            }
            words
        }
        AbiType::Tuple(fields) => {
            let mut words = Vec::new();
            for (i, field) in fields.iter().enumerate() {
                let field_words = symbolic_words_for_type(field, &format!("{name}_f{i}"), vars);
                words.extend(field_words);
            }
            words
        }
    }
}

/// Encode concrete calldata for a function with all-zero arguments
pub fn encode_zero_calldata(func: &AbiFunction) -> Vec<u8> {
    let selector = func.selector();
    let n_words = count_words(&func.inputs);
    let mut data = vec![0u8; 4 + n_words * 32];
    data[..4].copy_from_slice(&selector);
    data
}

fn count_words(params: &[AbiParam]) -> usize {
    params.iter().map(|p| words_for_type(&p.ty)).sum()
}

fn words_for_type(ty: &AbiType) -> usize {
    match ty {
        AbiType::Bytes | AbiType::SolString => 2,
        AbiType::Array(inner, None) => 1 + words_for_type(inner),
        AbiType::Array(inner, Some(n)) => n * words_for_type(inner),
        AbiType::Tuple(fields) => fields.iter().map(|f| words_for_type(f)).sum(),
        _ => 1,
    }
}

/// Build symbolic message for a check_ function
pub fn build_symbolic_message(
    func: &AbiFunction,
    callee: [u8; 20],
    caller: [u8; 20],
) -> crate::state::Message {
    let sym = SymbolicCalldata::from_function(func);
    crate::state::Message {
        caller,
        callee,
        origin: caller,
        callvalue: Expr::Concrete(U256::zero()),
        calldata: sym.concrete_prefix,
        calldata_sym: sym.sym_words,
        gas: 30_000_000,
        is_static: false,
        depth: 0,
    }
}
