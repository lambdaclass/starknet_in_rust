#![allow(unused_imports)]
use std::{collections::HashMap, vec, io::Bytes};

use cairo_lang_starknet::casm_contract_class::CasmContractClass;
use cairo_vm::felt::felt_str;
use lazy_static::lazy_static;
use num_traits::Zero;
use starknet_contract_class::EntryPointType;
use crate::{
    definitions::{block_context::{BlockContext, StarknetChainId}, constants::CONSTRUCTOR_ENTRY_POINT_SELECTOR},
    state::{
        cached_state::CachedState, in_memory_state_reader::InMemoryStateReader, ExecutionResourcesManager, state_api::{State, StateReader},
    }, Felt252, transaction::{InvokeFunction, DeployAccount, error::TransactionError}, execution::{TransactionExecutionContext, execution_entry_point::ExecutionEntryPoint, CallType}, utils::calculate_sn_keccak,
};
pub const ERC20_CONTRACT_PATH: &str = "starknet_programs/cairo2/ERC20.casm";
use crate::{
    state::state_cache::StorageEntry,
    utils::{felt_to_hash, Address, ClassHash},
};

use super::{
    get_contract_class, new_starknet_block_context_for_testing, ACCOUNT_CONTRACT_PATH, ACTUAL_FEE,
    TEST_ACCOUNT_CONTRACT_ADDRESS, TEST_ACCOUNT_CONTRACT_CLASS_HASH, TEST_CLASS_HASH,
    TEST_CONTRACT_ADDRESS, TEST_CONTRACT_PATH, TEST_ERC20_ACCOUNT_BALANCE_KEY,
    TEST_ERC20_CONTRACT_CLASS_HASH,
};

pub fn call_contract<T: State + StateReader>(
    contract_address: Felt252,
    entrypoint_selector: Felt252,
    calldata: Vec<Felt252>,
    state: &mut T,
    block_context: BlockContext,
    caller_address: Address,
) -> Result<Vec<Felt252>, TransactionError> {
    let contract_address = Address(contract_address);
    let class_hash = state.get_class_hash_at(&contract_address)?;
    let nonce = state.get_nonce_at(&contract_address)?;

    // TODO: Revisit these parameters
    let transaction_hash = 0.into();
    let signature = vec![];
    let max_fee = 1000000000;
    let initial_gas = 1000000000;
    let caller_address = caller_address;
    let version = 0;

    let execution_entrypoint = ExecutionEntryPoint::new(
        contract_address.clone(),
        calldata,
        entrypoint_selector,
        caller_address,
        EntryPointType::External,
        Some(CallType::Delegate),
        Some(class_hash),
        initial_gas,
    );

    let mut tx_execution_context = TransactionExecutionContext::new(
        contract_address,
        transaction_hash,
        signature,
        max_fee,
        nonce,
        block_context.invoke_tx_max_n_steps(),
        version.into(),
    );

    let call_info = execution_entrypoint.execute(
        state,
        &block_context,
        &mut ExecutionResourcesManager::default(),
        &mut tx_execution_context,
        false,
    )?;

    Ok(call_info.retdata)
}

#[test]
fn deploy_erc20_cairo2_without_constructor() {
    // INSERT ERC20 IN MEMORY
    let program_data = include_bytes!("../../starknet_programs/cairo2/erc20.casm");
    let contract_class: CasmContractClass = serde_json::from_slice(program_data).unwrap();
    
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

    let mut state = CachedState::new(state_reader, None, Some(contract_class_cache));

    // ACCOUNT 1
    let program_data_account = include_bytes!("../../starknet_programs/cairo2/hello_world_account.casm");
    let contract_class_account: CasmContractClass = serde_json::from_slice(program_data_account).unwrap();

    state
        .set_compiled_class(
            &felt_str!("1"),
            contract_class_account,
        )
        .unwrap();

    let contract_address_salt =
        felt_str!("2669425616857739096022668060305620640217901643963991674344872184515580705509");

    let internal_deploy_account = DeployAccount::new(
        felt_str!("1")
            .clone()
            .to_be_bytes(),
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
        None,
    )
    .unwrap();

    let account_address_1 = internal_deploy_account
        .execute(&mut state, &Default::default())
        .unwrap().validate_info.unwrap().contract_address;

    println!("account_address_1: {:?}", account_address_1.clone());
        
    // ACCOUNT 2
    let program_data_account = include_bytes!("../../starknet_programs/cairo2/hello_world_account.casm");
    let contract_class_account: CasmContractClass = serde_json::from_slice(program_data_account).unwrap();

    state
        .set_compiled_class(
            &felt_str!("1"),
            contract_class_account,
        )
        .unwrap();

    let contract_address_salt =
        felt_str!("123123123123123");

    let internal_deploy_account = DeployAccount::new(
        felt_str!("1")
            .clone()
            .to_be_bytes(),
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
        None,
    )
    .unwrap();

    let account_address_2 = internal_deploy_account
        .execute(&mut state, &Default::default())
        .unwrap().validate_info.unwrap().contract_address;
    
    // END OF ACCOUNTS

    // CONSTRUCTOR CALLDATA FOR ERC20
    let name_ = Felt252::from_bytes_be(b"some-token");
    let symbol_ = Felt252::from_bytes_be(b"my-super-awesome-token");
    let decimals_ = Felt252::from(24);
    let initial_supply = Felt252::from(1000);
    let recipient = account_address_1.clone().0;
    let calldata = vec![name_, symbol_, decimals_, initial_supply, recipient];

    // CONSTRUCTOR
    let _internal_deploy_account = DeployAccount::new(
        class_hash
            .clone(),
        0,
        1.into(),
        Felt252::zero(),
        calldata.clone(),
        vec![
            felt_str!(
                "3233776396904427614006684968846859029149676045084089832563834729503047027074"
            ),
            felt_str!(
                "707039245213420890976709143988743108543645298941971188668773816813012281203"
            ),
        ],
        felt_str!("123123123123123"),
        StarknetChainId::TestNet.to_felt(),
        None,
    )
    .unwrap().execute(&mut state, &Default::default());

    println!("deploying contract: {:?}", _internal_deploy_account);

    // let entrypoint_selector = Felt252::from_bytes_be(&calculate_sn_keccak(b"fake_constructor"));
    // let _retdata = call_contract(
    //     address.0.clone(),
    //     entrypoint_selector.clone().into(),
    //     calldata,
    //     &mut state,
    //     BlockContext::default(),
    //     account_address_1.clone().into(),
    // )
    // .unwrap();
    // println!("constructor retadata: {:?}", _retdata);
    // println!("message: {:?}", std::str::from_utf8(&Felt252::to_be_bytes(&_retdata[0])));

    // TRANSFER
    let entrypoint_selector = Felt252::from_bytes_be(&calculate_sn_keccak(b"transfer"));
    let calldata = vec![account_address_2.clone().0, Felt252::from(100)];

    let _retdata = call_contract(
        address.clone().0,
        entrypoint_selector.clone().into(),
        calldata,
        &mut state,
        BlockContext::default(),
        account_address_1.clone().into(),
    )
    .unwrap();
    
    println!("transfer retadata: {:?}", _retdata);
    println!("message: {:?}", std::str::from_utf8(&Felt252::to_be_bytes(&_retdata[0])));

    // GET BALANCE ACCOUNT 1
    let entrypoint_selector = Felt252::from_bytes_be(&calculate_sn_keccak(b"balance_of"));
    let retdata = call_contract(
        address.clone().0,
        entrypoint_selector.clone().into(),
        vec![account_address_1.clone().0],
        &mut state,
        BlockContext::default(),
        account_address_1.clone().into(),
    )
    .unwrap();

    println!("balance account 1: {:?}", retdata);
    // GET BALANCE ACCOUNT 2
    let entrypoint_selector = Felt252::from_bytes_be(&calculate_sn_keccak(b"balance_of"));
    let retdata = call_contract(
        address.0,
        entrypoint_selector.clone().into(),
        vec![account_address_2.clone().0],
        &mut state,
        BlockContext::default(),
        account_address_1.clone().into(),
    )
    .unwrap();

    println!("balance account 2: {:?}", retdata);

    println!("message: {:?}", std::str::from_utf8(&Felt252::to_be_bytes(&retdata[0])));
    assert_eq!(retdata, vec![89.into()]);
}