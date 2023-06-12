#![deny(warnings)]
#![forbid(unsafe_code)]
#![cfg_attr(coverage_nightly, feature(no_coverage))]

use business_logic::{
    execution::TransactionExecutionInfo,
    state::state_api::{State, StateReader},
    transaction::{error::TransactionError, Transaction},
};
use definitions::general_config::TransactionContext;

#[cfg(test)]
#[macro_use]
extern crate assert_matches;

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

pub fn execute_transaction<T: State + StateReader>(
    tx: Transaction,
    state: &mut T,
    config: TransactionContext,
) -> Result<TransactionExecutionInfo, TransactionError> {
    tx.execute(state, &config)
}
