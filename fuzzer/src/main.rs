#[macro_use]
extern crate honggfuzz;
use std::{collections::HashMap, path::PathBuf};

use felt::Felt;
use std::io::{BufReader, Read, Write};
use std::io;
use num_traits::Zero;
// use starknet_rs::services::api::{contract_class_errors::ContractClassError, contract_class::ContractClass};
use starknet_rs::{
    business_logic::{
        execution::{
            execution_entry_point::ExecutionEntryPoint,
            objects::{CallInfo, CallType, TransactionExecutionContext},
        },
        fact_state::{
            contract_state::ContractState, in_memory_state_reader::InMemoryStateReader,
            state::ExecutionResourcesManager,
        },
        state::cached_state::CachedState,
    },
    definitions::{constants::TRANSACTION_VERSION, general_config::StarknetGeneralConfig},
    services::api::contract_class::{ContractClass, EntryPointType},
    utils::{calculate_sn_keccak, Address},
};
use tempfile::NamedTempFile;
use std::fs::File;


fn main() {
    println!("Starting fuzzer");
    loop {
        fuzz!(|data: &[u8]| {
        let init_contract_class = try_from_data(data);

        if init_contract_class.is_ok() {

            // ---------------------------------------------------------
            //  Create program and entry point types for contract class
            // ---------------------------------------------------------
            let contract_class = init_contract_class.unwrap();
            let entry_points_by_type = contract_class.entry_points_by_type().clone();

            let fib_entrypoint_selector = entry_points_by_type
                .get(&starknet_rs::services::api::contract_class::EntryPointType::External)
                .unwrap()
                .get(0)
                .unwrap()
                .selector()
                .clone();


            //* --------------------------------------------
            //*    Create state reader with class hash data
            //* --------------------------------------------

            let mut contract_class_cache = HashMap::new();

            //  ------------ contract data --------------------

            let address = Address(1111.into());
            let class_hash = [1; 32];
            let contract_state = ContractState::new(class_hash, 3.into(), HashMap::new());

            contract_class_cache.insert(class_hash, contract_class);
            let mut state_reader = InMemoryStateReader::new(HashMap::new(), HashMap::new());
            state_reader
                .contract_states_mut()
                .insert(address.clone(), contract_state);

            //* ---------------------------------------
            //*    Create state with previous data
            //* ---------------------------------------

            let mut state = CachedState::new(state_reader, Some(contract_class_cache));

            //* ------------------------------------
            //*    Create execution entry point
            //* ------------------------------------

            let calldata = [1.into(), 1.into(), 10.into()].to_vec();
            let caller_address = starknet_rs::utils::Address(0000.into());
            let entry_point_type = starknet_rs::services::api::contract_class::EntryPointType::External;
            let entrypoint = starknet_rs::business_logic::execution::execution_entry_point::ExecutionEntryPoint::new(
                address,
                calldata.clone(),
                fib_entrypoint_selector.clone(),
                caller_address,
                entry_point_type,
                Some(starknet_rs::business_logic::execution::objects::CallType::Delegate),
                Some(class_hash),
            );

            //* --------------------
            //*   Execute contract
            //* ---------------------
            let general_config = starknet_rs::definitions::general_config::StarknetGeneralConfig::default();
            let tx_execution_context = starknet_rs::business_logic::execution::objects::TransactionExecutionContext::new(
                Address(0.into()),
                Felt::zero(),
                Vec::new(),
                0,
                10.into(),
                general_config.invoke_tx_max_n_steps(),
                TRANSACTION_VERSION,
            );
            let mut resources_manager = starknet_rs::business_logic::fact_state::state::ExecutionResourcesManager::default();

            entrypoint.execute(
                &mut state,
                &general_config,
                &mut resources_manager,
                &tx_execution_context
            )
            .unwrap();
        }
        
        });
    }
}

fn try_from_data(data: &[u8]) -> io::Result<ContractClass> {
    let raw_contract_class: starknet_api::state::ContractClass =
        serde_json::from_slice(data)?;
    println!("raw_contract_class: {:?}", raw_contract_class);

    let contract_class = ContractClass::from(raw_contract_class);
    Ok(contract_class)
}
