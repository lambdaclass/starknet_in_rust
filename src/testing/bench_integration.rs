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
fn test_invoke() {
    let mut starknet_state = StarknetState::new(None);
    let path = PathBuf::from("src/testing/test.json");
    let contract_class = ContractClass::try_from(path).unwrap();
    //let calldata = [10.into()].to_vec();
    let contract_address_salt = Address(1.into());

    let (contract_address, _exec_info) = starknet_state
        .deploy(contract_class, vec![], contract_address_salt)
        .unwrap();

    // main() selector
    let main_selector = Felt::from_str_radix(
        "112e35f48499939272000bd72eb840e502ca4c3aefa8800992e8defb746e0c9",
        16,
    )
    .unwrap();

    // Statement **not** in blockifier.
    starknet_state
        .state
        .cache_mut()
        .nonce_initial_values_mut()
        .insert(contract_address.clone(), Felt::zero());

    for i in 0..1 {
        starknet_state
            .invoke_raw(
                contract_address.clone(),
                main_selector.clone(),
                [1.into(), 1.into(), 15000.into()].into(),
                0,
                Some(Vec::new()),
                Some(Felt::from(i)),
            )
            .unwrap();
    }
}
