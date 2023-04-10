#![deny(warnings)]

use felt::Felt252;
use num_traits::Zero;
use starknet_crypto::{pedersen_hash, FieldElement};
use starknet_rs::{
    business_logic::{
        execution::{
            execution_entry_point::ExecutionEntryPoint,
            objects::{CallInfo, CallType, TransactionExecutionContext},
        },
        fact_state::{
            in_memory_state_reader::InMemoryStateReader, state::ExecutionResourcesManager,
        },
        state::{cached_state::CachedState, state_api::State},
        transaction::{error::TransactionError, objects::internal_deploy::InternalDeploy},
    },
    definitions::{constants::TRANSACTION_VERSION, general_config::StarknetGeneralConfig},
    services::api::contract_classes::contract_class::{ContractClass, EntryPointType},
    utils::{calculate_sn_keccak, Address},
};
use std::{collections::HashSet, path::PathBuf};

pub struct CallConfig<'a> {
    pub state: &'a mut CachedState<InMemoryStateReader>,
    pub caller_address: &'a Address,
    pub address: &'a Address,
    pub class_hash: &'a [u8; 32],
    pub general_config: &'a StarknetGeneralConfig,
    pub resources_manager: &'a mut ExecutionResourcesManager,
}

pub fn get_accessed_keys(variable_name: &str, fields: Vec<Vec<FieldElement>>) -> HashSet<[u8; 32]> {
    let variable_hash = calculate_sn_keccak(variable_name.as_bytes());
    let variable_hash = FieldElement::from_bytes_be(&variable_hash).unwrap();

    let keys = fields
        .iter()
        .map(|field| {
            field
                .iter()
                .fold(variable_hash, |hash, f| pedersen_hash(&hash, f))
        })
        .collect::<Vec<FieldElement>>();

    let mut accessed_storage_keys: HashSet<[u8; 32]> = HashSet::new();

    for key in keys {
        accessed_storage_keys.insert(key.to_bytes_be());
    }

    accessed_storage_keys
}

pub fn get_entry_points(
    function_name: &str,
    address: &Address,
    class_hash: &[u8; 32],
    calldata: &[Felt252],
    caller_address: &Address,
) -> (ExecutionEntryPoint, Felt252) {
    //* ------------------------------------
    //*    Create entry point selector
    //* ------------------------------------
    let entrypoint_selector =
        Felt252::from_bytes_be(&calculate_sn_keccak(function_name.as_bytes()));

    //* ------------------------------------
    //*    Create execution entry point
    //* ------------------------------------

    let entry_point_type = EntryPointType::External;

    (
        ExecutionEntryPoint::new(
            address.clone(),
            calldata.to_vec(),
            entrypoint_selector.clone(),
            caller_address.clone(),
            entry_point_type,
            Some(CallType::Delegate),
            Some(*class_hash),
        ),
        entrypoint_selector,
    )
}

pub fn execute_entry_point(
    function_name: &str,
    calldata: &[Felt252],
    call_config: &mut CallConfig,
) -> Result<CallInfo, TransactionError> {
    // Entry point for init pool
    let (exec_entry_point, _) = get_entry_points(
        function_name,
        call_config.address,
        call_config.class_hash,
        calldata,
        call_config.caller_address,
    );

    //* --------------------
    //*   Execute contract
    //* ---------------------
    let tx_execution_context = TransactionExecutionContext::new(
        Address(0.into()),
        Felt252::zero(),
        Vec::new(),
        0,
        10.into(),
        call_config.general_config.invoke_tx_max_n_steps(),
        TRANSACTION_VERSION,
    );

    exec_entry_point.execute(
        call_config.state,
        call_config.general_config,
        call_config.resources_manager,
        &tx_execution_context,
    )
}

pub fn deploy(
    state: &mut CachedState<InMemoryStateReader>,
    path: &str,
    config: &StarknetGeneralConfig,
) -> (Address, [u8; 32]) {
    let path = PathBuf::from(path);
    let contract_class = ContractClass::try_from(path).unwrap();

    let internal_deploy = InternalDeploy::new(
        Address(0.into()),
        contract_class.clone(),
        vec![],
        0.into(),
        0,
    )
    .unwrap();
    let class_hash = internal_deploy.class_hash();
    state
        .set_contract_class(&class_hash, &contract_class)
        .unwrap();

    let tx_execution_info = internal_deploy.apply(state, config).unwrap();

    let call_info = tx_execution_info.call_info.unwrap();
    let contract_address = call_info.contract_address;
    let class_hash = call_info.class_hash.unwrap();

    (contract_address, class_hash)
}
