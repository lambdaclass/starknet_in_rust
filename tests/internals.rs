use felt::{felt_str, Felt};
use lazy_static::lazy_static;
use num_traits::Zero;
use starknet_rs::{
    business_logic::{
        fact_state::{contract_state::ContractState, in_memory_state_reader::InMemoryStateReader},
        state::{cached_state::CachedState, state_api::StateReader},
        transaction::objects::internal_invoke_function::InternalInvokeFunction,
    },
    definitions::{
        constants::EXECUTE_ENTRY_POINT_SELECTOR, general_config::StarknetGeneralConfig,
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
            felt_to_hash(&*TEST_ERC20_ACCOUNT_BALANCE_KEY),
        ))
        .unwrap();
    assert_eq!(value, &2.into());

    let class_hash = state.get_class_hash_at(&*TEST_CONTRACT_ADDRESS).unwrap();
    assert_eq!(class_hash, &felt_to_hash(&*TEST_CLASS_HASH));

    let contract_class = state
        .get_contract_class(&felt_to_hash(&*TEST_ERC20_CONTRACT_CLASS_HASH))
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
        EntryPointType::External,
        calldata,
        TransactionType::InvokeFunction,
        0,
        Felt::zero(),
        Felt::zero(),
        vec![],
        0,
        Felt::zero(),
    )
}

#[test]
fn test_invoke_tx() {
    let (starknet_general_config, state) = &mut create_account_tx_test_state().unwrap();
    // func __execute__{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr}(
    //     contract_address, selector: felt, calldata_len: felt, calldata: felt*
    // ) -> (retdata_size: felt, retdata: felt*) {
    //     let (retdata_size: felt, retdata: felt*) = call_contract(
    //         contract_address=contract_address,
    //         function_selector=selector,
    //         calldata_size=calldata_len,
    //         calldata=calldata,
    //     );
    //     return (retdata_size=retdata_size, retdata=retdata);
    // }

    // TODO Should add builtins?
    let Address(test_contract_address) = TEST_CONTRACT_ADDRESS.clone();
    let calldata = vec![
        test_contract_address.clone(), // CONTRACT_ADDRESS
        Felt::from_bytes_be(&calculate_sn_keccak(b"return_result")), // CONTRACT FUNCTION SELECTOR
        Felt::from(1),                 // CONTRACT_CALLDATA LEN
        Felt::from(2),                 // CONTRACT_CALLDATA
    ]; // ACA TENGO QUE AGREGAR EL HASH DEL ENTRYPOINT, LOS PARAMS Y EL ADDRESS DEL CONTRATO
    let invoke_tx = invoke_tx(calldata.clone());

    // Extract invoke transaction fields for testing, as it is consumed when creating an account
    // transaction.
    let result = invoke_tx
        ._apply_specific_concurrent_changes(state, starknet_general_config)
        .unwrap();

    println!("result = {:?}", result);
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
