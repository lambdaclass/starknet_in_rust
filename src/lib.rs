#![deny(warnings)]
#![forbid(unsafe_code)]
#![cfg_attr(coverage_nightly, feature(no_coverage))]

#[cfg(test)]
#[macro_use]
extern crate assert_matches;

// Re-exports
pub use cairo_lang_starknet::casm_contract_class::CasmContractClass;
pub use cairo_lang_starknet::contract_class::ContractClass;
pub use cairo_lang_starknet::contract_class::ContractClass as SierraContractClass;
pub use cairo_vm::felt::Felt252;
pub use starknet_contract_class::EntryPointType;

pub mod business_logic;
pub mod core;
pub mod definitions;
pub mod hash_utils;
pub mod parser_errors;
pub mod runner;
pub mod serde_structs;
pub mod services;
pub mod storage;
pub mod syscalls;
pub mod testing;
pub mod utils;
