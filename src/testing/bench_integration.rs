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
    // 1) deploy dummy account (TODO)
    // 1) deploy fibonacci
    // 2) invoke call over fibonacci from dummy account

    let mut starknet_state = StarknetState::new(Some(StarknetGeneralConfig::new(
        StarknetOsConfig::new(StarknetChainId::TestNet, Address(felt_str!("4097")), 0),
        0,
        0,
        Default::default(),
        1_000_000,
        0,
        BlockInfo::empty(Address(felt_str!("4096"))),
    )));

    // deploy account
    let account_path = PathBuf::from("starknet_programs/account_without_validation.json");
    let account_contract_class = ContractClass::try_from(account_path).unwrap();
    let account_address_salt = Address(0.into());
    let (account_address, _exec_info) = starknet_state
        .deploy(account_contract_class.clone(), vec![], account_address_salt)
        .unwrap();

    // Statement **not** in blockifier.
    starknet_state
        .state
        .cache_mut()
        .nonce_initial_values_mut()
        .insert(account_address.clone(), Felt::zero());

    // deploy fibonacci
    let fibonacci_path = PathBuf::from("starknet_programs/fibonacci.json");
    let fibonacci_contract_class = ContractClass::try_from(fibonacci_path).unwrap();
    let contract_address_salt = Address(1.into());

    let (fibonacci_contract_address, _exec_info) = starknet_state
        .deploy(
            fibonacci_contract_class.clone(),
            vec![],
            contract_address_salt,
        )
        .unwrap();

    // Statement **not** in blockifier.
    starknet_state
        .state
        .cache_mut()
        .nonce_initial_values_mut()
        .insert(fibonacci_contract_address.clone(), Felt::zero());

    // Invoke fibonacci from account

    // fibonacci selector
    let fibonacci_selector = Felt::from_str_radix(
        "112e35f48499939272000bd72eb840e502ca4c3aefa8800992e8defb746e0c9",
        16,
    )
    .unwrap();

    let Address(fibonacci_addr_felt) = fibonacci_contract_address.clone();
    let calldata = [
        fibonacci_addr_felt,
        fibonacci_selector.clone(),
        3.into(),
        1.into(),
        1.into(),
        10.into(),
    ]
    .to_vec();
    let tx_info = starknet_state
        .invoke_raw(
            account_address,
            EXECUTE_ENTRY_POINT_SELECTOR.clone(),
            calldata,
            100,
            Some(Vec::new()),
            Some(Felt::zero()),
        )
        .unwrap();

    // expected result
    // ----- calculate fib class hash ---------
    let hash = compute_class_hash(&fibonacci_contract_class).unwrap();
    let fib_class_hash = felt_to_hash(&hash);

    let address =
        felt_str!("2066790681318687707025847340457605657642478884993868155391041767964612021885");
    let mut actual_resources = HashMap::new();
    actual_resources.insert("l1_gas_usage".to_string(), 0);

    let expected_info = TransactionExecutionInfo {
        validate_info: None,
        call_info: Some(CallInfo {
            caller_address: Address(Felt::zero()),
            call_type: Some(CallType::Call),
            contract_address: Address(address),
            code_address: None,
            class_hash: Some(fib_class_hash),
            entry_point_selector: Some(fibonacci_selector),
            entry_point_type: Some(EntryPointType::External),
            calldata: vec![1.into(), 1.into(), 10.into()],
            retdata: vec![144.into()],
            ..Default::default()
        }),
        actual_resources,
        tx_type: Some(TransactionType::InvokeFunction),
        ..Default::default()
    };

    assert_eq!(tx_info, expected_info);
}
