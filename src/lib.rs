#![deny(warnings)]
#![forbid(unsafe_code)]
#![cfg_attr(coverage_nightly, feature(no_coverage))]

use business_logic::{
    state::state_api::{State, StateReader},
    transaction::{error::TransactionError, transactions::Transaction},
};
use cairo_vm::felt::Felt252;
use definitions::general_config::StarknetGeneralConfig;

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

pub fn call_contract<T: State + StateReader>(
    tx: Transaction,
    state: &mut T,
    config: StarknetGeneralConfig,
) -> Result<Vec<Felt252>, TransactionError> {
    let tx_info = tx.execute(state, &config)?;

    if let Some(call_info) = tx_info.call_info {
        Ok(call_info.retdata)
    } else {
        Ok(vec![])
    }
}
