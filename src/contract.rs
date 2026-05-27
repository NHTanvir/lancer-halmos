//! Test contract discovery and check_ / invariant_ function enumeration.

use std::collections::HashMap;
use regex::Regex;

use crate::abi::{AbiFunction, StateMutability};
use crate::artifacts::Contract;

/// A discovered test function to run
#[derive(Debug, Clone)]
pub struct TestCase {
    pub contract_name: String,
    pub function_name: String,
    pub is_invariant: bool,
    pub func: AbiFunction,
    pub deployed_bytecode: Vec<u8>,
    pub setup_bytecode: Option<Vec<u8>>,
}

/// Discover all test cases in a contract matching the function prefix pattern
pub fn discover_tests(
    contract: &Contract,
    function_pattern: &str,
) -> Vec<TestCase> {
    let re = match Regex::new(function_pattern) {
        Ok(r) => r,
        Err(e) => {
            tracing::warn!("Invalid function pattern '{}': {}", function_pattern, e);
            return vec![];
        }
    };

    contract.abi.iter()
        .filter(|f| re.is_match(&f.name))
        .filter(|f| !f.name.starts_with("setUp"))
        .map(|f| TestCase {
            contract_name: contract.name.clone(),
            function_name: f.name.clone(),
            is_invariant: f.name.starts_with("invariant_"),
            func: f.clone(),
            deployed_bytecode: contract.deployed_bytecode.clone(),
            setup_bytecode: None,
        })
        .collect()
}

/// Find the setUp() function in a contract's ABI
pub fn find_setup_function(contract: &Contract) -> Option<&AbiFunction> {
    contract.abi.iter().find(|f| f.name == "setUp")
}

/// Find targetContract(), targetSelector() calls (for invariant testing)
pub fn find_invariant_targets(contract: &Contract) -> Vec<String> {
    // These are determined at runtime via cheatcodes; return empty here
    // The actual targets are registered during setUp() execution
    vec![]
}

/// Check if a function is a valid check_ function
pub fn is_check_function(f: &AbiFunction) -> bool {
    f.name.starts_with("check_")
}

/// Check if a function is a valid invariant_ function
pub fn is_invariant_function(f: &AbiFunction) -> bool {
    f.name.starts_with("invariant_")
}

/// Group test contracts by name
pub fn group_by_contract<'a>(tests: &'a [TestCase]) -> HashMap<&'a str, Vec<&'a TestCase>> {
    let mut map: HashMap<&'a str, Vec<&'a TestCase>> = HashMap::new();
    for t in tests {
        map.entry(&t.contract_name).or_default().push(t);
    }
    map
}

/// Print a summary of discovered tests
pub fn summarize(tests: &[TestCase]) -> String {
    let check_count = tests.iter().filter(|t| !t.is_invariant).count();
    let inv_count = tests.iter().filter(|t| t.is_invariant).count();
    format!(
        "Discovered {} check_ function(s) and {} invariant_ function(s)",
        check_count, inv_count
    )
}
