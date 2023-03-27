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

#[test]
fn test_invoke1000() {
    let mut starknet_state = StarknetState::new(None);
    let path = PathBuf::from("starknet_programs/first_contract.json");
    let contract_class = ContractClass::try_from(path).unwrap();
    //let calldata = [10.into()].to_vec();
    let contract_address_salt = Address(1.into());

    let (contract_address, _exec_info) = starknet_state
        .deploy(contract_class.clone(), vec![], contract_address_salt)
        .unwrap();

    // increase_balance selector
    let increase_balance_selector = Felt::from_str_radix(
        "362398bec32bc0ebb411203221a35a0301193a96f317ebe5e40be9f60d15320",
        16,
    )
    .unwrap();

    // get_balance selector
    let get_balance_selector = Felt::from_str_radix(
        "39e11d48192e4333233c7eb19d10ad67c362bb28580c604d67884c85da39695",
        16,
    )
    .unwrap();

    // Statement **not** in blockifier.
    starknet_state
        .state
        .cache_mut()
        .nonce_initial_values_mut()
        .insert(contract_address.clone(), Felt::zero());

    for i in (0..2001).step_by(2) {
        starknet_state
            .invoke_raw(
                contract_address.clone(),
                increase_balance_selector.clone(),
                [10.into()].into(),
                0,
                Some(Vec::new()),
                Some(Felt::from(i)),
            )
            .unwrap();

        let result = starknet_state
            .invoke_raw(
                contract_address.clone(),
                get_balance_selector.clone(),
                vec![],
                0,
                Some(Vec::new()),
                Some(Felt::from(i + 1)),
            )
            .unwrap();

        assert_eq!(
            result.call_info.unwrap().retdata,
            vec![Felt::from(((i / 2) + 1) * 10)]
        );
    }
}

#[test]
fn test_invoke5000() {
    let mut starknet_state = StarknetState::new(None);
    let path = PathBuf::from("starknet_programs/first_contract.json");
    let contract_class = ContractClass::try_from(path).unwrap();
    //let calldata = [10.into()].to_vec();
    let contract_address_salt = Address(1.into());

    let (contract_address, _exec_info) = starknet_state
        .deploy(contract_class.clone(), vec![], contract_address_salt)
        .unwrap();

    // increase_balance selector
    let increase_balance_selector = Felt::from_str_radix(
        "362398bec32bc0ebb411203221a35a0301193a96f317ebe5e40be9f60d15320",
        16,
    )
    .unwrap();

    // get_balance selector
    let get_balance_selector = Felt::from_str_radix(
        "39e11d48192e4333233c7eb19d10ad67c362bb28580c604d67884c85da39695",
        16,
    )
    .unwrap();

    // Statement **not** in blockifier.
    starknet_state
        .state
        .cache_mut()
        .nonce_initial_values_mut()
        .insert(contract_address.clone(), Felt::zero());

    for i in (0..10001).step_by(2) {
        starknet_state
            .invoke_raw(
                contract_address.clone(),
                increase_balance_selector.clone(),
                [10.into()].into(),
                0,
                Some(Vec::new()),
                Some(Felt::from(i)),
            )
            .unwrap();

        let result = starknet_state
            .invoke_raw(
                contract_address.clone(),
                get_balance_selector.clone(),
                vec![],
                0,
                Some(Vec::new()),
                Some(Felt::from(i + 1)),
            )
            .unwrap();

        assert_eq!(
            result.call_info.unwrap().retdata,
            vec![Felt::from(((i / 2) + 1) * 10)]
        );
    }
}

#[test]
fn test_invoke10000() {
    let mut starknet_state = StarknetState::new(None);
    let path = PathBuf::from("starknet_programs/first_contract.json");
    let contract_class = ContractClass::try_from(path).unwrap();
    //let calldata = [10.into()].to_vec();
    let contract_address_salt = Address(1.into());

    let (contract_address, _exec_info) = starknet_state
        .deploy(contract_class.clone(), vec![], contract_address_salt)
        .unwrap();

    // increase_balance selector
    let increase_balance_selector = Felt::from_str_radix(
        "362398bec32bc0ebb411203221a35a0301193a96f317ebe5e40be9f60d15320",
        16,
    )
    .unwrap();

    // get_balance selector
    let get_balance_selector = Felt::from_str_radix(
        "39e11d48192e4333233c7eb19d10ad67c362bb28580c604d67884c85da39695",
        16,
    )
    .unwrap();

    // Statement **not** in blockifier.
    starknet_state
        .state
        .cache_mut()
        .nonce_initial_values_mut()
        .insert(contract_address.clone(), Felt::zero());

    for i in (0..20001).step_by(2) {
        starknet_state
            .invoke_raw(
                contract_address.clone(),
                increase_balance_selector.clone(),
                [10.into()].into(),
                0,
                Some(Vec::new()),
                Some(Felt::from(i)),
            )
            .unwrap();

        let result = starknet_state
            .invoke_raw(
                contract_address.clone(),
                get_balance_selector.clone(),
                vec![],
                0,
                Some(Vec::new()),
                Some(Felt::from(i + 1)),
            )
            .unwrap();

        assert_eq!(
            result.call_info.unwrap().retdata,
            vec![Felt::from(((i / 2) + 1) * 10)]
        );
    }
}
