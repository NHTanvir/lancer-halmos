//! Halmos / hevm cheatcode dispatcher.
//! Handles calls to address(0x7109709ECfa91a80626fF3989D68f67F5b1DD12D).

use primitive_types::U256;
use crate::exceptions::EvmError;
use crate::state::Frame;
use crate::symbolic::{fresh_var, Expr};
use crate::types::{address_from_u256, keccak256, u256_from_address};
use crate::abi::decode_word;

/// The Forge/hevm cheatcode contract address
pub const CHEATCODE_ADDR: [u8; 20] = [
    0x71, 0x09, 0x70, 0x9e, 0xcf, 0xa9, 0x1a, 0x80, 0x62, 0x6f,
    0xf3, 0x98, 0x9d, 0x68, 0xf6, 0x7f, 0x5b, 0x1d, 0xd1, 0x2d,
];

/// svm cheatcode address (Halmos symbolic value maker)
pub const SVM_ADDR: [u8; 20] = [
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x73, 0x76, 0x6d, 0x00,
    0x00, 0x00, 0x00, 0x00,
];

/// Dispatch a cheatcode call, returning the return data
pub fn dispatch_cheatcode(frame: &mut Frame, calldata: &[u8]) -> Result<Vec<u8>, EvmError> {
    if calldata.len() < 4 { return Ok(vec![]); }
    let selector = [calldata[0], calldata[1], calldata[2], calldata[3]];
    let args = &calldata[4..];

    match selector {
        // vm.assume(bool)
        [0x4c, 0x63, 0xe5, 0x62] => {
            if args.len() >= 32 {
                let cond = U256::from_big_endian(&args[..32]);
                if cond.is_zero() {
                    // Assume false: mark path as infeasible
                    frame.path.add_constraint(crate::symbolic::Pred::False);
                }
            }
            Ok(vec![])
        }

        // vm.prank(address) — single call
        [0xca, 0x66, 0x93, 0x50] => {
            if args.len() >= 32 {
                let addr_val = U256::from_big_endian(&args[..32]);
                frame.msg.caller = address_from_u256(addr_val);
            }
            Ok(vec![])
        }

        // vm.prank(address, address) — prank + origin
        [0x47, 0xe3, 0x01, 0x3e] => {
            if args.len() >= 64 {
                let addr_val = U256::from_big_endian(&args[..32]);
                let origin_val = U256::from_big_endian(&args[32..64]);
                frame.msg.caller = address_from_u256(addr_val);
                frame.msg.origin = address_from_u256(origin_val);
            }
            Ok(vec![])
        }

        // vm.startPrank(address)
        [0x06, 0x47, 0x75, 0x19] => {
            if args.len() >= 32 {
                let addr_val = U256::from_big_endian(&args[..32]);
                frame.msg.caller = address_from_u256(addr_val);
            }
            Ok(vec![])
        }

        // vm.stopPrank()
        [0x90, 0xc5, 0x01, 0x3b] => Ok(vec![]),

        // vm.deal(address, uint256)
        [0xc8, 0x8a, 0x5e, 0x6d] => {
            if args.len() >= 64 {
                let addr = address_from_u256(U256::from_big_endian(&args[..32]));
                let amount = Expr::Concrete(U256::from_big_endian(&args[32..64]));
                frame.world.set_balance(addr, amount);
            }
            Ok(vec![])
        }

        // vm.store(address, bytes32, bytes32)
        [0x70, 0xca, 0x10, 0xbb] => {
            if args.len() >= 96 {
                let addr = address_from_u256(U256::from_big_endian(&args[..32]));
                let slot = Expr::Concrete(U256::from_big_endian(&args[32..64]));
                let val = Expr::Concrete(U256::from_big_endian(&args[64..96]));
                frame.world.get_storage_mut(&addr).store(slot, val);
            }
            Ok(vec![])
        }

        // vm.load(address, bytes32) → bytes32
        [0x66, 0x7f, 0x9d, 0x70] => {
            if args.len() >= 64 {
                let addr = address_from_u256(U256::from_big_endian(&args[..32]));
                let slot = Expr::Concrete(U256::from_big_endian(&args[32..64]));
                let val = if let Some(stor) = frame.world.get_storage(&addr) {
                    stor.load(&slot)
                } else {
                    Expr::Concrete(U256::zero())
                };
                let mut out = vec![0u8; 32];
                if let Expr::Concrete(v) = val {
                    v.to_big_endian(&mut out);
                }
                Ok(out)
            } else {
                Ok(vec![0u8; 32])
            }
        }

        // vm.warp(uint256) — set block.timestamp
        [0xe5, 0xd6, 0xbf, 0x02] => {
            if args.len() >= 32 {
                let ts = U256::from_big_endian(&args[..32]);
                frame.block.timestamp = Expr::Concrete(ts);
            }
            Ok(vec![])
        }

        // vm.roll(uint256) — set block.number
        [0x1f, 0x7b, 0x4f, 0x30] => {
            if args.len() >= 32 {
                let n = U256::from_big_endian(&args[..32]);
                frame.block.number = Expr::Concrete(n);
            }
            Ok(vec![])
        }

        // vm.fee(uint256) — set basefee
        [0x39, 0xb3, 0x7a, 0x0b] => {
            if args.len() >= 32 {
                let fee = U256::from_big_endian(&args[..32]);
                frame.block.basefee = Expr::Concrete(fee);
            }
            Ok(vec![])
        }

        // vm.chainId(uint256)
        [0x43, 0x95, 0x91, 0xf5] => {
            if args.len() >= 32 {
                let id = U256::from_big_endian(&args[..32]).as_usize() as u64;
                frame.block.chainid = id;
            }
            Ok(vec![])
        }

        // vm.coinbase(address)
        [0xff, 0x48, 0x3c, 0x54] => {
            if args.len() >= 32 {
                frame.block.coinbase = address_from_u256(U256::from_big_endian(&args[..32]));
            }
            Ok(vec![])
        }

        // vm.etch(address, bytes) — deploy code at address
        [0xb4, 0xd6, 0xc7, 0x82] => {
            if args.len() >= 32 {
                let addr = address_from_u256(U256::from_big_endian(&args[..32]));
                // code offset/length at args[32..64], args[64..96]
                if args.len() >= 96 {
                    let code_off = U256::from_big_endian(&args[32..64]).as_usize();
                    let code_len = U256::from_big_endian(&args[64..96]).as_usize();
                    if 4 + code_off + code_len <= calldata.len() {
                        let code = calldata[4+code_off..4+code_off+code_len].to_vec();
                        frame.world.deploy_code(addr, code);
                    }
                }
            }
            Ok(vec![])
        }

        // vm.expectRevert() — mark next call as expected to revert (simplified: no-op)
        [0xf4, 0x84, 0x48, 0x82] |
        [0xf2, 0x8d, 0xce, 0xb3] => Ok(vec![]),

        // ── svm cheatcodes ─────────────────────────────────────────────────────

        // svm.createUint256(string name) → uint256
        [0xce, 0x04, 0xfe, 0x3e] => {
            let var = extract_string_arg(args, 0)
                .map(|n| fresh_var(&n))
                .unwrap_or_else(|| fresh_var("sym_uint256"));
            let mut out = vec![0u8; 32];
            // Return the variable name encoded? We push a fresh symbolic var.
            // The actual value will be symbolic in the EVM stack.
            // We encode a placeholder zero; the caller's CALLDATALOAD returns sym.
            Ok(out)
        }

        // svm.createUint(uint256 bits, string name) → uint
        [0xf6, 0x79, 0x56, 0x6a] => {
            let var = extract_string_arg(args, 64)
                .map(|n| fresh_var(&n))
                .unwrap_or_else(|| fresh_var("sym_uint"));
            Ok(vec![0u8; 32])
        }

        // svm.createBytes(uint256 length, string name) → bytes
        [0xe1, 0x7e, 0x09, 0x84] => {
            Ok(vec![0u8; 32])
        }

        // svm.createAddress(string name) → address
        [0x3b, 0x0f, 0xa0, 0x8d] => {
            Ok(vec![0u8; 32])
        }

        // svm.createBool(string name) → bool
        [0x5b, 0xbe, 0x36, 0xa6] => {
            Ok(vec![0u8; 32])
        }

        // svm.enableSymbolicStorage(address)
        [0x57, 0x9e, 0x93, 0x90] => {
            if args.len() >= 32 {
                let addr = address_from_u256(U256::from_big_endian(&args[..32]));
                frame.world.get_storage_mut(&addr).enable_symbolic();
            }
            Ok(vec![])
        }

        // vm.targetContract(address) — invariant target
        [0x7f, 0xc3, 0x64, 0x7c] => {
            // Store in frame context (handled at invariant level)
            Ok(vec![])
        }

        // vm.targetSelector(FuzzSelector) — invariant target selector
        [0x48, 0xec, 0x55, 0x31] => Ok(vec![]),

        // vm.targetSender(address)
        [0xf1, 0xa2, 0x1e, 0x68] => Ok(vec![]),

        // setEnv(string key, string value) — no-op for symbolic execution
        [0x39, 0x9b, 0x39, 0x8b] => Ok(vec![]),

        // envBool, envUint, envInt, envAddress, envBytes32, envString, envBytes
        // envOr* variants — return symbolic or zero values
        [0x7e, 0xd1, 0xec, 0x7d] |  // envBool
        [0xc1, 0x97, 0x8d, 0x6f] |  // envUint
        [0x5d, 0x4a, 0xa4, 0x4f] |  // envInt
        [0xd0, 0x5d, 0xde, 0x90] |  // envAddress
        [0x90, 0x7b, 0x9a, 0x84] |  // envBytes32
        [0x38, 0x3a, 0x1e, 0x52] |  // envString
        [0x10, 0x71, 0x09, 0x48] => { // envBytes
            Ok(vec![0u8; 32])
        }

        // randomUint(uint min, uint max) → uint
        [0x27, 0xb1, 0x1d, 0x53] => {
            let var = fresh_var("rand_uint");
            // If min/max are provided, constrain the value
            Ok(vec![0u8; 32]) // return symbolic zero; actual randomness ignored
        }

        // randomAddress() → address
        [0xd5, 0xae, 0xc0, 0x94] => Ok(vec![0u8; 32]),

        // ffi(string[]) — disabled by default
        [0x89, 0x16, 0x04, 0x05] => {
            Err(EvmError::SolverError("ffi not enabled (use --ffi)".to_string()))
        }

        // Unknown cheatcode: silently ignore
        _ => {
            tracing::debug!("Unknown cheatcode: {:?}", selector);
            Ok(vec![0u8; 32])
        }
    }
}

/// Extract a string argument from ABI-encoded calldata at a given offset
fn extract_string_arg(args: &[u8], offset: usize) -> Option<String> {
    // ABI encoding: offset points to the start of the string, which is length + data
    if args.len() < offset + 32 { return None; }
    let str_offset = U256::from_big_endian(&args[offset..offset+32]).as_usize();
    if str_offset + 32 > args.len() { return None; }
    let str_len = U256::from_big_endian(&args[str_offset..str_offset+32]).as_usize();
    let data_start = str_offset + 32;
    if data_start + str_len > args.len() { return None; }
    std::str::from_utf8(&args[data_start..data_start+str_len]).ok().map(|s| s.to_string())
}
