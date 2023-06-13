#![allow(warnings)]
#![forbid(unsafe_code)]
#![cfg_attr(coverage_nightly, feature(no_coverage))]

use crate::business_logic::transaction::InvokeFunction;
use business_logic::{
    execution::TransactionExecutionContext, state::state_api::StateReader,
    transaction::error::TransactionError,
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

pub fn simulate_transaction<S: StateReader>(
    transaction: InvokeFunction,
    state: S,
    transaction_context: TransactionContext,
    skip_validate: bool,
) -> Result<(), TransactionError> {
    transaction.simulate_transaction(state, transaction_context, skip_validate);
    Ok(())
}
