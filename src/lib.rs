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

#[cfg(test)]
mod test {
    use std::collections::HashMap;

    use cairo_lang_starknet::casm_contract_class::CasmContractClass;
    use cairo_vm::felt::Felt252;
    use num_traits::Zero;

    use crate::{business_logic::{transaction::{transactions::Transaction, InvokeFunction}, state::{in_memory_state_reader::InMemoryStateReader, cached_state::CachedState}}, utils::{Address, ClassHash}, estimate_fee, definitions::general_config::StarknetChainId};

    #[test]
    fn estimate_fee_test() {
        let program_data = include_bytes!("../starknet_programs/cairo1/fibonacci.casm");
        let contract_class: CasmContractClass = serde_json::from_slice(program_data).unwrap();
        let entrypoints = contract_class.clone().entry_points_by_type;
        let entrypoint_selector = &entrypoints.external.get(0).unwrap().selector;

        let mut contract_class_cache = HashMap::new();

        let address = Address(1111.into());
        let class_hash: ClassHash = [1; 32];
        let nonce = Felt252::zero();

        contract_class_cache.insert(class_hash, contract_class);
        let mut state_reader = InMemoryStateReader::default();
        state_reader
            .address_to_class_hash_mut()
            .insert(address.clone(), class_hash);
        state_reader
            .address_to_nonce_mut()
            .insert(address.clone(), nonce);

        let state = CachedState::new(state_reader, None, Some(contract_class_cache));
        let calldata = [1.into(), 1.into(), 10.into()].to_vec();
        let invoke_function = InvokeFunction::new(address, entrypoint_selector.into(), 100_000_000, 1, calldata, vec![], StarknetChainId::TestNet.to_felt(), Some(1.into()), None).unwrap();
        let transaction = Transaction::InvokeFunction(invoke_function);

        let estimated_fee = estimate_fee(&transaction, state).unwrap();
        assert_eq!(estimated_fee, (0, 0))
    }
}
