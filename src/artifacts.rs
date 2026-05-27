//! Foundry build artifact loader.
//! Reads from `out/` directory (forge build output).

use std::path::{Path, PathBuf};
use std::collections::HashMap;
use anyhow::{anyhow, Result};
use serde::Deserialize;
use serde_json::Value;

use crate::abi::{AbiFunction, JsonAbi, JsonAbiEntry};

/// A compiled Foundry contract
#[derive(Debug, Clone)]
pub struct Contract {
    pub name: String,
    pub source_file: String,
    pub abi: Vec<AbiFunction>,
    pub bytecode: Vec<u8>,
    pub deployed_bytecode: Vec<u8>,
    pub storage_layout: Option<StorageLayout>,
    pub source_map: Option<String>,
}

impl Contract {
    pub fn get_function(&self, name: &str) -> Option<&AbiFunction> {
        self.abi.iter().find(|f| f.name == name)
    }

    pub fn get_functions_matching(&self, pattern: &str) -> Vec<&AbiFunction> {
        use regex::Regex;
        if let Ok(re) = Regex::new(pattern) {
            self.abi.iter().filter(|f| re.is_match(&f.name)).collect()
        } else {
            self.abi.iter().filter(|f| f.name.starts_with(pattern)).collect()
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct StorageLayout {
    pub storage: Vec<StorageEntry>,
    pub types: HashMap<String, StorageType>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct StorageEntry {
    pub label: String,
    pub slot: String,
    pub offset: u32,
    #[serde(rename = "type")]
    pub type_id: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct StorageType {
    pub encoding: String,
    pub label: String,
    #[serde(rename = "numberOfBytes")]
    pub number_of_bytes: String,
}

/// Load all contracts from a Foundry `out/` directory.
pub fn load_foundry_artifacts(root: &Path) -> Result<HashMap<String, Contract>> {
    let out_dir = root.join("out");
    if !out_dir.exists() {
        return Err(anyhow!("No 'out/' directory found at {:?}. Run `forge build` first.", out_dir));
    }

    let mut contracts = HashMap::new();

    // Walk out/ for *.json files (excluding metadata files)
    for entry in walkdir::WalkDir::new(&out_dir)
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_type().is_file())
    {
        let path = entry.path();
        if path.extension().map(|e| e == "json").unwrap_or(false) {
            let filename = path.file_name().unwrap().to_string_lossy();
            // Skip .metadata.json
            if filename.ends_with(".metadata.json") { continue; }

            match load_artifact(path) {
                Ok(Some(contract)) => {
                    contracts.insert(contract.name.clone(), contract);
                }
                Ok(None) => {}
                Err(e) => {
                    tracing::debug!("Skipping {:?}: {}", path, e);
                }
            }
        }
    }

    Ok(contracts)
}

/// Load a single artifact JSON file
fn load_artifact(path: &Path) -> Result<Option<Contract>> {
    let content = std::fs::read_to_string(path)?;
    let json: Value = serde_json::from_str(&content)?;

    // Must have "abi" and "bytecode" fields
    let abi_json = json.get("abi").ok_or_else(|| anyhow!("no abi field"))?;
    let bytecode_json = json.get("bytecode")
        .or_else(|| json.get("deployedBytecode"));

    // Contract name from filename: "ContractName.json"
    let name = path.file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("Unknown")
        .to_string();

    // Skip test helper artifacts (interfaces, etc.)
    if name.is_empty() { return Ok(None); }

    // Parse ABI
    let abi_entries: Vec<JsonAbiEntry> = serde_json::from_value(abi_json.clone())
        .unwrap_or_default();
    let abi: Vec<AbiFunction> = abi_entries.iter()
        .filter_map(|e| e.to_abi_function())
        .collect();

    // Parse bytecode
    let bytecode = parse_bytecode_field(&json, "bytecode");
    let deployed_bytecode = parse_bytecode_field(&json, "deployedBytecode");

    // Parse storage layout
    let storage_layout = json.get("storageLayout")
        .and_then(|v| serde_json::from_value::<StorageLayout>(v.clone()).ok());

    // Parse source map
    let source_map = json.get("sourceMap")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());

    // Infer source file from path
    let source_file = path.parent()
        .and_then(|p| p.file_name())
        .and_then(|n| n.to_str())
        .unwrap_or("")
        .to_string();

    Ok(Some(Contract {
        name,
        source_file,
        abi,
        bytecode,
        deployed_bytecode,
        storage_layout,
        source_map,
    }))
}

fn parse_bytecode_field(json: &Value, field: &str) -> Vec<u8> {
    let hex_str = json.get(field)
        .and_then(|v| v.get("object").or(Some(v)))
        .and_then(|v| v.as_str())
        .unwrap_or("");

    let hex_str = hex_str.trim_start_matches("0x");
    if hex_str == "__UNLINKED__" || hex_str.is_empty() {
        return vec![];
    }
    hex::decode(hex_str).unwrap_or_default()
}

/// Locate a single contract by name across the artifact map
pub fn find_contract<'a>(artifacts: &'a HashMap<String, Contract>, name: &str) -> Option<&'a Contract> {
    artifacts.get(name)
}

/// Discover all test contracts (name ends in "Test" or matches pattern)
pub fn find_test_contracts<'a>(
    artifacts: &'a HashMap<String, Contract>,
    contract_pattern: &Option<String>,
) -> Vec<&'a Contract> {
    artifacts.values().filter(|c| {
        if let Some(pat) = contract_pattern {
            use regex::Regex;
            Regex::new(pat).map(|re| re.is_match(&c.name)).unwrap_or(false)
        } else {
            // Default: contracts with Test suffix
            c.name.ends_with("Test") || c.name.ends_with("Tests")
                || c.name.starts_with("Test") // TestFoo style
        }
    }).collect()
}
