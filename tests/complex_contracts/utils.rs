#![deny(warnings)]

use cairo_vm::felt::Felt252;
use num_traits::Zero;
use starknet_crypto::{pedersen_hash, FieldElement};
use starknet_in_rust::{
    definitions::{
        block_context::{BlockContext, StarknetChainId},
        constants::TRANSACTION_VERSION,
    },
    execution::{
        execution_entry_point::ExecutionEntryPoint, CallInfo, CallType, TransactionExecutionContext,
    },
    services::api::contract_classes::deprecated_contract_class::ContractClass,
    state::{cached_state::CachedState, state_api::State},
    state::{in_memory_state_reader::InMemoryStateReader, ExecutionResourcesManager},
    transaction::{error::TransactionError, Deploy},
    utils::{calculate_sn_keccak, Address},
};
use starknet_in_rust::{ContractEntryPoint, EntryPointType};
use std::collections::{HashMap, HashSet};

pub struct CallConfig<'a> {
    pub state: &'a mut CachedState<InMemoryStateReader>,
    pub caller_address: &'a Address,
    pub address: &'a Address,
    pub class_hash: &'a [u8; 32],
    pub entry_points_by_type: &'a HashMap<EntryPointType, Vec<ContractEntryPoint>>,
    pub entry_point_type: &'a EntryPointType,
    pub block_context: &'a BlockContext,
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

    if keys.is_empty() {
        accessed_storage_keys.insert(variable_hash.to_bytes_be());
    }
    for key in keys {
        accessed_storage_keys.insert(key.to_bytes_be());
    }

    accessed_storage_keys
}

pub fn get_entry_points(
    function_name: &str,
    entry_point_type: &EntryPointType,
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

    (
        ExecutionEntryPoint::new(
            address.clone(),
            calldata.to_vec(),
            entrypoint_selector.clone(),
            caller_address.clone(),
            *entry_point_type,
            Some(CallType::Delegate),
            Some(*class_hash),
            300000,
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
        call_config.entry_point_type,
        call_config.address,
        call_config.class_hash,
        calldata,
        call_config.caller_address,
    );

    //* --------------------
    //*   Execute contract
    //* ---------------------
    let mut tx_execution_context = TransactionExecutionContext::new(
        Address(0.into()),
        Felt252::zero(),
        Vec::new(),
        0,
        10.into(),
        call_config.block_context.invoke_tx_max_n_steps(),
        TRANSACTION_VERSION.clone(),
    );

    exec_entry_point.execute(
        call_config.state,
        call_config.block_context,
        call_config.resources_manager,
        &mut tx_execution_context,
        false,
        call_config.block_context.invoke_tx_max_n_steps(),
    )
}

pub fn deploy(
    state: &mut CachedState<InMemoryStateReader>,
    path: &str,
    calldata: &[Felt252],
    block_context: &BlockContext,
    hash_value: Option<Felt252>,
) -> Result<(Address, [u8; 32]), TransactionError> {
    let contract_class = ContractClass::from_path(path).unwrap();

    let internal_deploy = match hash_value {
        None => Deploy::new(
            0.into(),
            contract_class.clone(),
            calldata.to_vec(),
            StarknetChainId::TestNet.to_felt(),
            0.into(),
        )?,
        Some(hash_value) => Deploy::new_with_tx_hash(
            0.into(),
            contract_class.clone(),
            calldata.to_vec(),
            0.into(),
            hash_value,
        )?,
    };
    let class_hash = internal_deploy.class_hash();
    state.set_contract_class(&class_hash, &contract_class)?;

    let tx_execution_info = internal_deploy.apply(state, block_context)?;

    let call_info = tx_execution_info.call_info.unwrap();
    let contract_address = call_info.contract_address;
    let class_hash = call_info.class_hash.unwrap();

    Ok((contract_address, class_hash))
}
