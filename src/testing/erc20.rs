#![allow(unused_imports)]
use std::{collections::HashMap, io::Bytes, path::Path, vec};

use crate::{
    call_contract,
    definitions::{
        block_context::{BlockContext, StarknetChainId},
        constants::CONSTRUCTOR_ENTRY_POINT_SELECTOR,
    },
    execution::{
        execution_entry_point::ExecutionEntryPoint, CallType, TransactionExecutionContext,
    },
    services::api::contract_classes::deprecated_contract_class::ContractClass,
    state::{
        cached_state::CachedState,
        in_memory_state_reader::InMemoryStateReader,
        state_api::{State, StateReader},
        ExecutionResourcesManager,
    },
    transaction::{error::TransactionError, DeployAccount, InvokeFunction},
    utils::calculate_sn_keccak,
    EntryPointType, Felt252,
};
use cairo_lang_starknet::casm_contract_class::CasmContractClass;
use cairo_vm::felt::felt_str;
use lazy_static::lazy_static;
use num_traits::Zero;
pub const ERC20_CONTRACT_PATH: &str = "starknet_programs/cairo2/ERC20.casm";
use crate::{
    state::state_cache::StorageEntry,
    utils::{felt_to_hash, Address, ClassHash},
};

use super::{
    new_starknet_block_context_for_testing, ACCOUNT_CONTRACT_PATH, ACTUAL_FEE,
    TEST_ACCOUNT_CONTRACT_ADDRESS, TEST_ACCOUNT_CONTRACT_CLASS_HASH, TEST_CLASS_HASH,
    TEST_CONTRACT_ADDRESS, TEST_CONTRACT_PATH, TEST_ERC20_ACCOUNT_BALANCE_KEY,
    TEST_ERC20_CONTRACT_CLASS_HASH,
};

#[test]
fn test_erc20_cairo2() {
    // data to deploy
    let erc20_class_hash: ClassHash = [2; 32];
    let test_data = include_bytes!("../../starknet_programs/cairo2/erc20.casm");
    let test_contract_class: CasmContractClass = serde_json::from_slice(test_data).unwrap();

    // Create the deploy contract class
    let program_data = include_bytes!("../../starknet_programs/cairo2/deploy_erc20.casm");
    let contract_class: CasmContractClass = serde_json::from_slice(program_data).unwrap();
    let entrypoints = contract_class.clone().entry_points_by_type;
    let entrypoint_selector = &entrypoints.external.get(0).unwrap().selector;

    // Create state reader with class hash data
    let mut contract_class_cache = HashMap::new();

    let address = Address(1111.into());
    let class_hash: ClassHash = [1; 32];
    let nonce = Felt252::zero();

    contract_class_cache.insert(class_hash, contract_class);
    contract_class_cache.insert(erc20_class_hash, test_contract_class);

    let mut state_reader = InMemoryStateReader::default();
    state_reader
        .address_to_class_hash_mut()
        .insert(address.clone(), class_hash);
    state_reader
        .address_to_nonce_mut()
        .insert(address.clone(), nonce);

    // Create state from the state_reader and contract cache.
    let mut state = CachedState::new(state_reader, None, Some(contract_class_cache));

    let name_ = Felt252::from_bytes_be(b"some-token");
    let symbol_ = Felt252::from_bytes_be(b"my-super-awesome-token");
    let decimals_ = Felt252::from(24);
    let initial_supply = Felt252::from(1000);
    let recipient =
        felt_str!("397149464972449753182583229366244826403270781177748543857889179957856017275");
    let erc20_salt = felt_str!("1234");
    // arguments of deploy contract
    let calldata = vec![
        Felt252::from_bytes_be(&erc20_class_hash),
        erc20_salt,
        recipient,
        name_,
        decimals_,
        initial_supply,
        symbol_,
    ];
    // set up remaining structures

    let caller_address = Address(0000.into());
    let entry_point_type = EntryPointType::External;

    let exec_entry_point = ExecutionEntryPoint::new(
        address,
        calldata,
        Felt252::new(entrypoint_selector.clone()),
        caller_address,
        entry_point_type,
        Some(CallType::Delegate),
        Some(class_hash),
        100_000_000_000,
    );

    // Execute the entrypoint
    let block_context = BlockContext::default();
    let mut tx_execution_context = TransactionExecutionContext::new(
        Address(0.into()),
        Felt252::zero(),
        Vec::new(),
        0,
        10.into(),
        block_context.invoke_tx_max_n_steps(),
        1.into(),
    );
    let mut resources_manager = ExecutionResourcesManager::default();

    let call_info = exec_entry_point
        .execute(
            &mut state,
            &block_context,
            &mut resources_manager,
            &mut tx_execution_context,
            false,
        )
        .unwrap();
    let erc20_address = call_info.retdata.get(0).unwrap().clone();

    // ACCOUNT 1
    let program_data_account =
        include_bytes!("../../starknet_programs/cairo2/hello_world_account.casm");
    let contract_class_account: CasmContractClass =
        serde_json::from_slice(program_data_account).unwrap();

    state
        .set_compiled_class(&felt_str!("1"), contract_class_account)
        .unwrap();

    let contract_address_salt =
        felt_str!("2669425616857739096022668060305620640217901643963991674344872184515580705509");

    let internal_deploy_account = DeployAccount::new(
        felt_str!("1").to_be_bytes(),
        0,
        1.into(),
        Felt252::zero(),
        vec![2.into()],
        vec![
            felt_str!(
                "3233776396904427614006684968846859029149676045084089832563834729503047027074"
            ),
            felt_str!(
                "707039245213420890976709143988743108543645298941971188668773816813012281203"
            ),
        ],
        contract_address_salt,
        StarknetChainId::TestNet.to_felt(),
    )
    .unwrap();

    let account_address_1 = internal_deploy_account
        .execute(&mut state, &Default::default())
        .unwrap()
        .validate_info
        .unwrap()
        .contract_address;

    // ACCOUNT 2
    let program_data_account =
        include_bytes!("../../starknet_programs/cairo2/hello_world_account.casm");
    let contract_class_account: CasmContractClass =
        serde_json::from_slice(program_data_account).unwrap();

    state
        .set_compiled_class(&felt_str!("1"), contract_class_account)
        .unwrap();

    let contract_address_salt = felt_str!("123123123123123");

    let internal_deploy_account = DeployAccount::new(
        felt_str!("1").to_be_bytes(),
        0,
        1.into(),
        Felt252::zero(),
        vec![2.into()],
        vec![
            felt_str!(
                "3233776396904427614006684968846859029149676045084089832563834729503047027074"
            ),
            felt_str!(
                "707039245213420890976709143988743108543645298941971188668773816813012281203"
            ),
        ],
        contract_address_salt,
        StarknetChainId::TestNet.to_felt(),
    )
    .unwrap();

    let account_address_2 = internal_deploy_account
        .execute(&mut state, &Default::default())
        .unwrap()
        .validate_info
        .unwrap()
        .contract_address;

    // TRANSFER
    let entrypoint_selector = Felt252::from_bytes_be(&calculate_sn_keccak(b"transfer"));
    let calldata = vec![account_address_2.clone().0, Felt252::from(123)];

    let retdata = call_contract(
        erc20_address.clone(),
        entrypoint_selector,
        calldata,
        &mut state,
        BlockContext::default(),
        account_address_1.clone(),
    )
    .unwrap();

    assert!(retdata.is_empty());

    // GET BALANCE ACCOUNT 1
    let entrypoint_selector = Felt252::from_bytes_be(&calculate_sn_keccak(b"balance_of"));
    let retdata = call_contract(
        erc20_address.clone(),
        entrypoint_selector,
        vec![account_address_1.clone().0],
        &mut state,
        BlockContext::default(),
        account_address_1.clone(),
    )
    .unwrap();

    assert_eq!(retdata, vec![877.into()]);

    // GET BALANCE ACCOUNT 2
    let entrypoint_selector = Felt252::from_bytes_be(&calculate_sn_keccak(b"balance_of"));
    let retdata = call_contract(
        erc20_address,
        entrypoint_selector,
        vec![account_address_2.0],
        &mut state,
        BlockContext::default(),
        account_address_1,
    )
    .unwrap();

    assert_eq!(retdata, vec![123.into()]);
}
