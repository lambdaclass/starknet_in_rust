use std::{collections::HashMap, path::PathBuf};

use felt::{felt_str, Felt};
use num_traits::{Num, Zero};

use crate::{
    business_logic::{
        execution::objects::{CallInfo, CallType, TransactionExecutionInfo},
        state::state_api_objects::BlockInfo,
    },
    core::contract_address::starknet_contract_address::compute_class_hash,
    definitions::{
        constants::EXECUTE_ENTRY_POINT_SELECTOR,
        general_config::{StarknetChainId, StarknetGeneralConfig, StarknetOsConfig},
        transaction_type::TransactionType,
    },
    services::api::contract_class::{ContractClass, EntryPointType},
    testing::starknet_state::StarknetState,
    utils::{felt_to_hash, Address},
};

use lazy_static::lazy_static;

lazy_static! {
    // include_str! doesn't seem to work in CI
    static ref CONTRACT_CLASS: ContractClass = ContractClass::try_from(PathBuf::from(
        "starknet_programs/first_contract.json",
    )).unwrap();
}

#[test]
fn test_invoke() {
    const RUNS: usize = 10000;
    let mut starknet_state = StarknetState::new(None);
    let contract_address_salt = Address(1.into());

    let (contract_address, _exec_info) = starknet_state
        .deploy(CONTRACT_CLASS.to_owned(), vec![], contract_address_salt)
        .unwrap();

    // increase_balance() selector
    let increase_balance_selector =
        felt_str!("1530486729947006463063166157847785599120665941190480211966374137237989315360");
    let get_balance_selector =
        felt_str!("1636223440827086009537493065587328807418413867743950350615962740049133672085");

    // Statement **not** in blockifier.
    starknet_state
        .state
        .cache_mut()
        .nonce_initial_values_mut()
        .insert(contract_address.clone(), Felt::zero());

    for i in (0..RUNS * 2).step_by(2) {
        starknet_state
            .invoke_raw(
                contract_address.clone(),
                increase_balance_selector.clone(),
                vec![1000.into()],
                0,
                Some(Vec::new()),
                Some(Felt::from(i)),
            )
            .unwrap();

        starknet_state
            .invoke_raw(
                contract_address.clone(),
                get_balance_selector.clone(),
                vec![],
                0,
                Some(Vec::new()),
                Some(Felt::from(i + 1)),
            )
            .unwrap();
    }
}
