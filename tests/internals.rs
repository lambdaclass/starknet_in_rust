use cairo_rs::vm::runners::cairo_runner::ExecutionResources;
use felt::{felt_str, Felt};
use lazy_static::lazy_static;
use num_traits::{Num, Zero};
use starknet_rs::{
    business_logic::{
        execution::objects::{CallInfo, CallType, OrderedEvent, TransactionExecutionInfo},
        fact_state::{contract_state::ContractState, in_memory_state_reader::InMemoryStateReader},
        state::{cached_state::CachedState, state_api::StateReader},
        transaction::objects::internal_invoke_function::InternalInvokeFunction,
    },
    definitions::{
        constants::EXECUTE_ENTRY_POINT_SELECTOR,
        general_config::{StarknetChainId, StarknetGeneralConfig},
        transaction_type::TransactionType,
    },
    services::api::contract_class::{ContractClass, EntryPointType},
    utils::{calculate_sn_keccak, felt_to_hash, Address},
};
use std::{collections::HashMap, path::PathBuf};

const ACCOUNT_CONTRACT_PATH: &str = "starknet_programs/account_without_validation.json";
const ERC20_CONTRACT_PATH: &str = "starknet_programs/ERC20.json";
const TEST_CONTRACT_PATH: &str = "starknet_programs/test_contract.json";

lazy_static! {
    // Addresses.
    static ref TEST_ACCOUNT_CONTRACT_ADDRESS: Address = Address(felt_str!("257"));
    static ref TEST_CONTRACT_ADDRESS: Address = Address(felt_str!("256"));

    // Class hashes.
    static ref TEST_ACCOUNT_CONTRACT_CLASS_HASH: Felt = felt_str!("273");
    static ref TEST_CLASS_HASH: Felt = felt_str!("272");
    static ref TEST_ERC20_CONTRACT_CLASS_HASH: Felt = felt_str!("4112");

    // Storage keys.
    static ref TEST_ERC20_ACCOUNT_BALANCE_KEY: Felt =
        felt_str!("1192211877881866289306604115402199097887041303917861778777990838480655617515");
    static ref TEST_ERC20_SEQUENCER_BALANCE_KEY: Felt =
        felt_str!("3229073099929281304021185011369329892856197542079132996799046100564060768274");

    // Others.
    static ref ACTUAL_FEE: Felt = 2.into();
}

fn get_contract_class<P>(path: P) -> Result<ContractClass, Box<dyn std::error::Error>>
where
    P: Into<PathBuf>,
{
    Ok(ContractClass::try_from(path.into())?)
}

#[allow(dead_code)]
fn create_account_tx_test_state(
) -> Result<(StarknetGeneralConfig, CachedState<InMemoryStateReader>), Box<dyn std::error::Error>> {
    let general_config = StarknetGeneralConfig::new_for_testing();

    let test_contract_class_hash = TEST_CLASS_HASH.clone();
    let test_account_class_hash = TEST_ACCOUNT_CONTRACT_CLASS_HASH.clone();
    let test_erc20_class_hash = TEST_ERC20_CONTRACT_CLASS_HASH.clone();
    let class_hash_to_class = HashMap::from([
        (
            test_account_class_hash.clone(),
            get_contract_class(ACCOUNT_CONTRACT_PATH)?,
        ),
        (
            test_contract_class_hash.clone(),
            get_contract_class(TEST_CONTRACT_PATH)?,
        ),
        (
            test_erc20_class_hash.clone(),
            get_contract_class(ERC20_CONTRACT_PATH)?,
        ),
    ]);

    let test_contract_address = TEST_CONTRACT_ADDRESS.clone();
    let test_account_address = TEST_ACCOUNT_CONTRACT_ADDRESS.clone();
    let test_erc20_address = general_config
        .starknet_os_config()
        .fee_token_address()
        .clone();
    let address_to_class_hash = HashMap::from([
        (test_contract_address, test_contract_class_hash),
        (test_account_address, test_account_class_hash),
        (test_erc20_address.clone(), test_erc20_class_hash),
    ]);

    let test_erc20_account_balance_key = TEST_ERC20_ACCOUNT_BALANCE_KEY.clone();
    let test_erc20_sequencer_balance_key = TEST_ERC20_SEQUENCER_BALANCE_KEY.clone();
    let storage_view = HashMap::from([
        (
            (test_erc20_address.clone(), test_erc20_sequencer_balance_key),
            Felt::zero(),
        ),
        (
            (test_erc20_address, test_erc20_account_balance_key),
            ACTUAL_FEE.clone(),
        ),
    ]);

    let cached_state = CachedState::new(
        {
            let mut state_reader = InMemoryStateReader::new(HashMap::new(), HashMap::new());

            for (contract_address, class_hash) in address_to_class_hash {
                let storage_keys = storage_view
                    .iter()
                    .filter_map(|((k0, k1), v)| {
                        (k0 == &contract_address).then_some((k1.clone(), v.clone()))
                    })
                    .collect();

                state_reader.contract_states_mut().insert(
                    contract_address,
                    ContractState::new(felt_to_hash(&class_hash), Felt::zero(), storage_keys),
                );
            }

            state_reader
        },
        Some(
            class_hash_to_class
                .into_iter()
                .map(|(k, v)| (felt_to_hash(&k), v))
                .collect(),
        ),
    );

    Ok((general_config, cached_state))
}

#[test]
fn test_create_account_tx_test_state() {
    let (general_config, mut state) = create_account_tx_test_state().unwrap();

    let value = state
        .get_storage_at(&(
            general_config
                .starknet_os_config()
                .fee_token_address()
                .clone(),
            felt_to_hash(&TEST_ERC20_ACCOUNT_BALANCE_KEY),
        ))
        .unwrap();
    assert_eq!(value, &2.into());

    let class_hash = state.get_class_hash_at(&TEST_CONTRACT_ADDRESS).unwrap();
    assert_eq!(class_hash, &felt_to_hash(&TEST_CLASS_HASH));

    let contract_class = state
        .get_contract_class(&felt_to_hash(&TEST_ERC20_CONTRACT_CLASS_HASH))
        .unwrap();
    assert_eq!(
        contract_class,
        get_contract_class(ERC20_CONTRACT_PATH).unwrap()
    );
}

fn invoke_tx(calldata: Vec<Felt>) -> InternalInvokeFunction {
    InternalInvokeFunction::new(
        TEST_ACCOUNT_CONTRACT_ADDRESS.clone(),
        EXECUTE_ENTRY_POINT_SELECTOR.clone(),
        1,
        calldata,
        vec![],
        StarknetChainId::TestNet.to_felt(),
        Some(Felt::zero()),
    )
    .unwrap()
}

#[test]
fn test_invoke_tx() {
    println!("0");
    let (starknet_general_config, state) = &mut create_account_tx_test_state().unwrap();
    println!("1");
    // TODO Should add builtins?
    let Address(test_contract_address) = TEST_CONTRACT_ADDRESS.clone();
    let calldata = vec![
        test_contract_address.clone(), // CONTRACT_ADDRESS
        Felt::from_bytes_be(&calculate_sn_keccak(b"return_result")), // CONTRACT FUNCTION SELECTOR
        Felt::from(1),                 // CONTRACT_CALLDATA LEN
        Felt::from(2),                 // CONTRACT_CALLDATA
    ];
    let invoke_tx = invoke_tx(calldata.clone());
    println!("2");
    // Extract invoke transaction fields for testing, as it is consumed when creating an account
    // transaction.
    let result = invoke_tx.execute(state, starknet_general_config).unwrap();
    println!("3");
    let expected_validate_call_info = CallInfo {
        caller_address: Address(Felt::zero()),
        call_type: Some(CallType::Call),
        contract_address: TEST_CONTRACT_ADDRESS.clone(),
        code_address: None, // I'm not sure if this is correct.
        class_hash: None,
        entry_point_selector: Some(
            Felt::from_str_radix(
                "0162da33a4585851fe8d3af3c2a9c60b557814e221e0d4f30ff0b2189d9c7775",
                16,
            )
            .unwrap(),
        ),
        entry_point_type: Some(EntryPointType::External),
        calldata: vec![
            Felt::from(256),
            Felt::from_str_radix(
                "039a1491f76903a16feed0a6433bec78de4c73194944e1118e226820ad479701",
                16,
            )
            .unwrap(),
            Felt::from(1),
            Felt::from(2),
        ],
        retdata: vec![Felt::from(1)],
        execution_resources: ExecutionResources::default(),
        l2_to_l1_messages: vec![],
        internal_calls: vec![],
        events: vec![],
        ..Default::default()
    };

    let expected_execute_call_info = Some(CallInfo {
        caller_address: Address(Felt::zero()),
        call_type: Some(CallType::Call),
        contract_address: TEST_CONTRACT_ADDRESS.clone(),
        code_address: None, // I'm not sure if this is correct.
        class_hash: None,
        entry_point_selector: Some(
            Felt::from_str_radix(
                "015d40a3d6ca2ac30f4031e42be28da9b056fef9bb7357ac5e85627ee876e5ad",
                16,
            )
            .unwrap(),
        ),
        entry_point_type: Some(EntryPointType::External),
        calldata: vec![
            Felt::from(256),
            Felt::from_str_radix(
                "039a1491f76903a16feed0a6433bec78de4c73194944e1118e226820ad479701",
                16,
            )
            .unwrap(),
            Felt::from(1),
            Felt::from(2),
        ],
        retdata: vec![Felt::from(2)],
        execution_resources: ExecutionResources::default(),
        l2_to_l1_messages: vec![],
        internal_calls: vec![CallInfo {
            caller_address: TEST_ACCOUNT_CONTRACT_ADDRESS.clone(),
            call_type: Some(CallType::Call),
            class_hash: None,
            entry_point_selector: Some(
                Felt::from_str_radix(
                    "039a1491f76903a16feed0a6433bec78de4c73194944e1118e226820ad479701",
                    16,
                )
                .unwrap(),
            ),
            entry_point_type: Some(EntryPointType::External),
            calldata: vec![Felt::from(2)],
            retdata: vec![Felt::from(2)],
            events: vec![],
            l2_to_l1_messages: vec![],
            internal_calls: vec![],
            execution_resources: ExecutionResources::default(),
            ..Default::default()
        }],
        events: vec![],
        ..Default::default()
    });

    let expected_fee_transfer_info = CallInfo {
        caller_address: TEST_ACCOUNT_CONTRACT_ADDRESS.clone(),
        call_type: Some(CallType::Call),
        contract_address: TEST_CONTRACT_ADDRESS.clone(),
        code_address: None, // I'm not sure if this is correct.
        class_hash: None,
        entry_point_selector: Some(
            Felt::from_str_radix(
                "0083afd3f4caedc6eebf44246fe54e38c95e3179a5ec9ea81740eca5b482d12e",
                16,
            )
            .unwrap(),
        ),
        entry_point_type: Some(EntryPointType::External),
        calldata: vec![Felt::from(4096), Felt::from(1), Felt::zero()],
        retdata: vec![Felt::from(1)],
        execution_resources: ExecutionResources::default(),
        l2_to_l1_messages: vec![],
        internal_calls: vec![],
        events: vec![OrderedEvent {
            order: 0,
            keys: vec![Felt::from_str_radix(
                "0099cd8bde557814842a3121e8ddfd433a539b8c9f14bf31ebf108d12e6196e9",
                16,
            )
            .unwrap()],
            data: vec![
                Felt::from(257),
                Felt::from(4096),
                Felt::from(1),
                Felt::zero(),
            ],
        }],
        ..Default::default()
    };

    let expected_execution_info = TransactionExecutionInfo::new(
        Some(expected_validate_call_info),
        expected_execute_call_info,
        Some(expected_fee_transfer_info),
        1,
        HashMap::new(),
        Some(TransactionType::InvokeFunction),
    );

    assert_eq!(result, expected_execution_info);

    // // Build expected validate call info.
    // let expected_account_address = ContractAddress(patricia_key!(TEST_ACCOUNT_CONTRACT_ADDRESS));
    // let expected_validate_call_info = expected_validate_call_info(
    //     constants::VALIDATE_ENTRY_POINT_NAME,
    //     calldata,
    //     expected_account_address,
    // );

    // // Build expected execute call info.
    // let expected_return_result_calldata = vec![stark_felt!(2)];
    // let expected_return_result_call = CallEntryPoint {
    //     entry_point_selector: selector_from_name("return_result"),
    //     class_hash: None,
    //     entry_point_type: EntryPointType::External,
    //     calldata: Calldata(expected_return_result_calldata.clone().into()),
    //     storage_address: ContractAddress(patricia_key!(TEST_CONTRACT_ADDRESS)),
    //     caller_address: expected_account_address,
    // };
    // let expected_execute_call = CallEntryPoint {
    //     entry_point_selector: selector_from_name(constants::EXECUTE_ENTRY_POINT_NAME),
    //     ..expected_validate_call_info.call.clone()
    // };
    // let expected_return_result_retdata = Retdata(expected_return_result_calldata);
    // let expected_execute_call_info = Some(CallInfo {
    //     call: expected_execute_call,
    //     execution: CallExecution::from_retdata(Retdata(expected_return_result_retdata.0.clone())),
    //     inner_calls: vec![CallInfo {
    //         call: expected_return_result_call,
    //         execution: CallExecution::from_retdata(expected_return_result_retdata),
    //         ..Default::default()
    //     }],
    // });

    // // Build expected fee transfer call info.
    // let expected_actual_fee = actual_fee();
    // let expected_fee_transfer_call_info = expected_fee_transfer_call_info(
    //     starknet_general_config,
    //     expected_account_address,
    //     expected_actual_fee,
    // );

    // let expected_execution_info = TransactionExecutionInfo {
    //     validate_call_info: expected_validate_call_info,
    //     execute_call_info: expected_execute_call_info,
    //     fee_transfer_call_info: expected_fee_transfer_call_info,
    //     actual_fee: expected_actual_fee,
    //     actual_resources: ResourcesMapping::default(),
    // };

    // // Test execution info result.
    // assert_eq!(actual_execution_info, expected_execution_info);

    // // Test nonce update.
    // let nonce_from_state = *state.get_nonce_at(sender_address).unwrap();
    // assert_eq!(nonce_from_state, Nonce(stark_felt!(1)));

    // // Test final balances.
    // let expected_sequencer_balance = stark_felt!(expected_actual_fee.0 as u64);
    // validate_final_balances(
    //     state,
    //     starknet_general_config,
    //     expected_sequencer_balance,
    //     TEST_ERC20_ACCOUNT_BALANCE_KEY,
    // );
}
