#![deny(warnings)]
#![forbid(unsafe_code)]
#![cfg_attr(coverage_nightly, feature(no_coverage))]

use business_logic::{
    state::{cached_state::CachedState, state_api::StateReader},
    transaction::{error::TransactionError, transactions::Transaction},
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

/// Estimate the fee associated with transaction
pub fn estimate_fee<T>(
    transaction: &Transaction,
    state: T,
) -> Result<(u128, usize), TransactionError>
where
    T: StateReader,
{
    // This is used as a copy of the original state, we can update this cached state freely.
    let mut cached_state = CachedState::<T> {
        state_reader: state,
        cache: Default::default(),
        contract_classes: Default::default(),
        casm_contract_classes: Default::default(),
    };

    // Check if the contract is deployed.
    cached_state.get_class_hash_at(&transaction.contract_address())?;

    // execute the transaction with the fake state.
    let transaction_result =
        transaction.execute(&mut cached_state, &TransactionContext::default())?;

    if let Some(gas_usage) = transaction_result.actual_resources.get("l1_gas_usage") {
        let actual_fee = transaction_result.actual_fee;
        Ok((actual_fee, *gas_usage))
    } else {
        Err(TransactionError::ResourcesError)
    }
}
