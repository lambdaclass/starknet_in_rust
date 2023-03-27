#[macro_use]
extern crate honggfuzz;

use felt::Felt252;
use num_traits::Zero;
use cairo_rs::vm::runners::cairo_runner::ExecutionResources;
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

use std::{
    collections::{HashMap, HashSet},
    path::PathBuf,
};

use std::fs;
use std::process::Command;
use std::thread;
use std::time::Duration;
use tempfile::tempdir_in;
use std::fs::File;
use std::io::Write;


fn main() {
    println!("Starting fuzzer");
    let mut iteration = 0;
    fs::create_dir("cairo_programs").expect("Failed to create cairo_programs/ directory");
    loop {
        fuzz!(|data: &[u8]| {

            iteration += 1;

            // ---------------------------------------------------------
            //  Create the content of the .cairo file with a function that writes the random data in the counter
            // ---------------------------------------------------------
            let file_content1 = "
            %lang starknet
            from starkware.cairo.common.cairo_builtins import HashBuiltin
            
            @storage_var
            func _counter() -> (res: felt) {
            }
            
            @external
            func write_and_read{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr}() -> (res:felt) {
                _counter.write('";

            let input = data_to_ascii(data);
            
            let file_content2 = "');
                return _counter.read();
            }
            ";
            let file_name = format!("cairo_programs/output-{}.cairo", iteration);

            let file_content  = file_content1.to_owned() + &input + file_content2 ;

            println!("{:?}", file_content);
            // ---------------------------------------------------------
            //  Create the .cairo file 
            // ---------------------------------------------------------
            
            fs::write(file_name, file_content.as_bytes()).expect("Failed to write generated cairo program");

            // ---------------------------------------------------------
            //  Compile the .cairo file to create the .json file
            // ---------------------------------------------------------

            let cairo_file_name = format!("cairo_programs/output-{}.cairo", iteration);
            let json_file_name = format!("cairo_programs/output-{}.json", iteration);

            let _output = Command::new("starknet-compile")
                        .arg(cairo_file_name.clone())
                        .arg("--output")
                        .arg(json_file_name.clone())
                        .output()
                        .expect("failed to execute process");

            // ---------------------------------------------------------
            //  Create program and entry point types for contract class
            // ---------------------------------------------------------

            let path = PathBuf::from(&json_file_name);
            let contract_class = ContractClass::try_from(path).unwrap();

            let storage_entrypoint_selector = contract_class
                .entry_points_by_type()
                .get(&EntryPointType::External)
                .unwrap()
                .get(0)
                .unwrap()
                .selector()
                .clone();
            
            fs::remove_file(cairo_file_name).expect("Failed to remove generated cairo source");
            fs::remove_file(json_file_name).expect("Failed to remove generated cairo compiled program");

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

            let calldata = [].to_vec();
            let caller_address = Address(0000.into());
            let entry_point_type = EntryPointType::External;

            let exec_entry_point = ExecutionEntryPoint::new(
                address.clone(),
                calldata.clone(),
                storage_entrypoint_selector.clone(),
                caller_address,
                entry_point_type,
                Some(CallType::Delegate),
                Some(class_hash),
            );

            //* --------------------
            //*   Execute contract
            //* ---------------------
            let general_config = StarknetGeneralConfig::default();
            let tx_execution_context = TransactionExecutionContext::new(
                Address(0.into()),
                Felt252::zero(),
                Vec::new(),
                0,
                10.into(),
                general_config.invoke_tx_max_n_steps(),
                TRANSACTION_VERSION,
            );
            let mut resources_manager = ExecutionResourcesManager::default();

            let expected_key = calculate_sn_keccak("_counter".as_bytes());

            let mut expected_accessed_storage_keys = HashSet::new();
            expected_accessed_storage_keys.insert(expected_key);

            let expected_call_info = CallInfo {
                caller_address: Address(0.into()),
                call_type: Some(CallType::Delegate),
                contract_address: Address(1111.into()),
                entry_point_selector: Some(storage_entrypoint_selector),
                entry_point_type: Some(EntryPointType::External),
                calldata,
                retdata: [Felt252::from_bytes_be(data_to_ascii(data).as_bytes())].to_vec(),
                execution_resources: ExecutionResources::default(),
                class_hash: Some(class_hash),
                storage_read_values: vec![Felt252::from_bytes_be(data_to_ascii(data).as_bytes())],
                accessed_storage_keys: expected_accessed_storage_keys,
                ..Default::default()
            };
            
            assert_eq!(
                exec_entry_point
                    .execute(
                        &mut state,
                        &general_config,
                        &mut resources_manager,
                        &tx_execution_context
                    )
                    .unwrap(),
                expected_call_info
            );
            
            assert!(!state.cache().storage_writes().is_empty());
            assert_eq!(
                state
                    .cache()
                    .storage_writes()
                    .get(&(address, expected_key))
                    .cloned(),
                Some(Felt252::from_bytes_be(data_to_ascii(data).as_bytes()))
            );

        });
        thread::sleep(Duration::from_secs(1));
    }
}

fn data_to_ascii(data: &[u8]) -> String {
    let data_string = String::from_utf8_lossy(data);
    let mut chars = Vec::new();
    for i in data_string.chars() {
        if !i.is_ascii(){
            chars.push('X');     
        } else if (i.clone() as u32) < 40 {
            let num_string = (i.clone() as u32).to_string();
            for j in num_string.chars(){
                chars.push(j);
            }
        } else {
            chars.push(i);
        };
        
    }

    let mut data_ascii: String = chars.iter().collect();
    data_ascii.truncate(30);
    data_ascii
    
}
