//! ABI types and calldata encoding/decoding.
//! Minimal implementation covering types needed for symbolic calldata generation.

use primitive_types::U256;
use serde::Deserialize;

/// Solidity ABI types
#[derive(Debug, Clone, PartialEq)]
pub enum AbiType {
    Uint(u32),          // uint8..uint256
    Int(u32),           // int8..int256
    Address,
    Bool,
    BytesN(u32),        // bytes1..bytes32 (static fixed-size)
    Bytes,              // bytes (dynamic)
    SolString,          // string (dynamic)
    Array(Box<AbiType>, Option<usize>), // T[] or T[N]
    Tuple(Vec<AbiType>),
}

impl AbiType {
    /// Parse a Solidity type string
    pub fn parse(s: &str) -> Option<AbiType> {
        let s = s.trim();
        if let Some(inner) = s.strip_suffix("[]") {
            return Some(AbiType::Array(Box::new(AbiType::parse(inner)?), None));
        }
        if s.ends_with(']') {
            let open = s.rfind('[')?;
            let inner_type = &s[..open];
            let n: usize = s[open+1..s.len()-1].parse().ok()?;
            return Some(AbiType::Array(Box::new(AbiType::parse(inner_type)?), Some(n)));
        }
        if s.starts_with('(') {
            let inner = s.strip_prefix('(')?.strip_suffix(')')?;
            let parts = split_tuple_components(inner);
            let types: Option<Vec<_>> = parts.iter().map(|p| AbiType::parse(p)).collect();
            return Some(AbiType::Tuple(types?));
        }
        match s {
            "address" => Some(AbiType::Address),
            "bool" => Some(AbiType::Bool),
            "bytes" => Some(AbiType::Bytes),
            "string" => Some(AbiType::SolString),
            _ if s.starts_with("uint") => {
                let bits: u32 = s[4..].parse().unwrap_or(256);
                Some(AbiType::Uint(bits))
            }
            _ if s.starts_with("int") => {
                let bits: u32 = s[3..].parse().unwrap_or(256);
                Some(AbiType::Int(bits))
            }
            _ if s.starts_with("bytes") => {
                let n: u32 = s[5..].parse().ok()?;
                Some(AbiType::BytesN(n))
            }
            _ => None,
        }
    }

    /// Is this a dynamic type? (determines ABI encoding head/tail split)
    pub fn is_dynamic(&self) -> bool {
        match self {
            AbiType::Bytes | AbiType::SolString => true,
            AbiType::Array(_, None) => true,
            AbiType::Array(inner, Some(_)) => inner.is_dynamic(),
            AbiType::Tuple(fields) => fields.iter().any(|f| f.is_dynamic()),
            _ => false,
        }
    }

    /// Head size in bytes for ABI encoding
    pub fn head_size(&self) -> usize {
        if self.is_dynamic() { 32 } else { self.static_size() }
    }

    pub fn static_size(&self) -> usize {
        match self {
            AbiType::Uint(_) | AbiType::Int(_) | AbiType::Address | AbiType::Bool => 32,
            AbiType::BytesN(_) => 32,
            AbiType::Bytes | AbiType::SolString => 32, // offset only
            AbiType::Array(inner, Some(n)) => n * inner.head_size(),
            AbiType::Array(_, None) => 32,
            AbiType::Tuple(fields) => fields.iter().map(|f| f.head_size()).sum(),
        }
    }
}

/// Split "uint256,address,(bytes,uint32)" respecting nested parens
fn split_tuple_components(s: &str) -> Vec<String> {
    let mut parts = Vec::new();
    let mut depth = 0;
    let mut start = 0;
    for (i, c) in s.char_indices() {
        match c {
            '(' => depth += 1,
            ')' => depth -= 1,
            ',' if depth == 0 => {
                parts.push(s[start..i].trim().to_string());
                start = i + 1;
            }
            _ => {}
        }
    }
    if start < s.len() {
        parts.push(s[start..].trim().to_string());
    }
    parts
}

/// ABI function signature
#[derive(Debug, Clone)]
pub struct AbiFunction {
    pub name: String,
    pub inputs: Vec<AbiParam>,
    pub outputs: Vec<AbiParam>,
    pub state_mutability: StateMutability,
}

#[derive(Debug, Clone)]
pub struct AbiParam {
    pub name: String,
    pub ty: AbiType,
    pub components: Vec<AbiParam>, // for tuples
}

#[derive(Debug, Clone, PartialEq)]
pub enum StateMutability {
    Pure,
    View,
    NonPayable,
    Payable,
}

impl AbiFunction {
    /// Compute the 4-byte selector: keccak256(signature)[0..4]
    pub fn selector(&self) -> [u8; 4] {
        let sig = self.signature();
        let hash = crate::types::keccak256(sig.as_bytes());
        [hash[0], hash[1], hash[2], hash[3]]
    }

    /// Canonical function signature e.g. "foo(uint256,address)"
    pub fn signature(&self) -> String {
        let params: Vec<String> = self.inputs.iter().map(|p| abi_type_str(&p.ty)).collect();
        format!("{}({})", self.name, params.join(","))
    }
}

fn abi_type_str(ty: &AbiType) -> String {
    match ty {
        AbiType::Uint(n) => format!("uint{}", n),
        AbiType::Int(n) => format!("int{}", n),
        AbiType::Address => "address".to_string(),
        AbiType::Bool => "bool".to_string(),
        AbiType::BytesN(n) => format!("bytes{}", n),
        AbiType::Bytes => "bytes".to_string(),
        AbiType::SolString => "string".to_string(),
        AbiType::Array(inner, None) => format!("{}[]", abi_type_str(inner)),
        AbiType::Array(inner, Some(n)) => format!("{}[{}]", abi_type_str(inner), n),
        AbiType::Tuple(fields) => {
            let parts: Vec<_> = fields.iter().map(abi_type_str).collect();
            format!("({})", parts.join(","))
        }
    }
}

/// Encode a single U256 value as 32 bytes big-endian
pub fn encode_word(val: U256) -> Vec<u8> {
    let mut out = vec![0u8; 32];
    val.to_big_endian(&mut out);
    out
}

/// Encode a bytes4 selector prefix
pub fn encode_with_selector(selector: [u8; 4], args: &[u8]) -> Vec<u8> {
    let mut out = vec![0u8; 4 + args.len()];
    out[..4].copy_from_slice(&selector);
    out[4..].copy_from_slice(args);
    out
}

/// Decode a U256 from 32 bytes at offset
pub fn decode_word(data: &[u8], offset: usize) -> Option<U256> {
    if offset + 32 > data.len() { return None; }
    Some(U256::from_big_endian(&data[offset..offset+32]))
}

/// Parse JSON ABI from Foundry artifact
#[derive(Debug, Deserialize)]
pub struct JsonAbi {
    pub abi: Vec<JsonAbiEntry>,
}

#[derive(Debug, Deserialize)]
pub struct JsonAbiEntry {
    #[serde(rename = "type")]
    pub entry_type: String,
    pub name: Option<String>,
    #[serde(default)]
    pub inputs: Vec<JsonAbiInput>,
    #[serde(default)]
    pub outputs: Vec<JsonAbiInput>,
    #[serde(rename = "stateMutability", default)]
    pub state_mutability: Option<String>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct JsonAbiInput {
    pub name: String,
    #[serde(rename = "type")]
    pub input_type: String,
    #[serde(default)]
    pub components: Vec<JsonAbiInput>,
}

impl JsonAbiEntry {
    pub fn to_abi_function(&self) -> Option<AbiFunction> {
        if self.entry_type != "function" { return None; }
        let name = self.name.clone()?;
        let inputs: Vec<AbiParam> = self.inputs.iter().map(|i| json_input_to_param(i)).collect();
        let outputs: Vec<AbiParam> = self.outputs.iter().map(|o| json_input_to_param(o)).collect();
        let sm = match self.state_mutability.as_deref() {
            Some("pure") => StateMutability::Pure,
            Some("view") => StateMutability::View,
            Some("payable") => StateMutability::Payable,
            _ => StateMutability::NonPayable,
        };
        Some(AbiFunction { name, inputs, outputs, state_mutability: sm })
    }
}

fn json_input_to_param(i: &JsonAbiInput) -> AbiParam {
    let ty = if i.input_type == "tuple" {
        let fields: Vec<_> = i.components.iter().map(|c| {
            AbiType::parse(&c.input_type).unwrap_or(AbiType::Uint(256))
        }).collect();
        AbiType::Tuple(fields)
    } else {
        AbiType::parse(&i.input_type).unwrap_or(AbiType::Uint(256))
    };
    AbiParam {
        name: i.name.clone(),
        ty,
        components: i.components.iter().map(|c| json_input_to_param(c)).collect(),
    }
}
