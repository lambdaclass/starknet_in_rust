#![deny(warnings)]
#![forbid(unsafe_code)]
#![cfg_attr(coverage_nightly, feature(no_coverage))]

#[cfg(test)]
#[macro_use]
extern crate assert_matches;

pub mod core;
pub mod definitions;
pub mod execution;
pub mod fact_state;
pub mod hash_utils;
pub mod parser_errors;
pub mod runner;
pub mod serde_structs;
pub mod services;
pub mod state;
pub mod storage;
pub mod syscalls;
pub mod testing;
pub mod transaction;
pub mod utils;
