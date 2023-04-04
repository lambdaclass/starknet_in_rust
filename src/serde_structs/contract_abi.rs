use crate::services::api::contract_class::EntryPointType;
use serde::Deserialize;
use serde_json::Value;
use std::{collections::HashMap, fs::File, path::PathBuf};

#[allow(dead_code)]
#[derive(Deserialize, Debug)]
struct Signature {
    inputs: Value,
    name: String,
    outputs: Value,
    #[serde(default, rename = "stateMutability")]
    state_mutability: Option<String>,
    #[serde(rename = "type")]
    type_name: String,
}

pub fn read_abi(abi_name: &PathBuf) -> HashMap<String, (usize, EntryPointType)> {
    let abi: Vec<Signature> = serde_json::from_reader(&File::open(abi_name).unwrap()).unwrap();
    let mut func_type_counter: HashMap<String, usize> = HashMap::new();
    let mut result_hash_map: HashMap<String, (usize, EntryPointType)> = HashMap::new();

    for function in abi {
        let function_address = match func_type_counter.get(&function.type_name) {
            Some(number) => number + 1,
            None => 0,
        };

        let entry_point_type = match &function.type_name {
            type_name if type_name == "function" => EntryPointType::External,
            type_name if type_name == "constructor" => EntryPointType::Constructor,
            _ => EntryPointType::L1Handler,
        };

        func_type_counter.insert(function.type_name, function_address);
        result_hash_map.insert(function.name, (function_address, entry_point_type));
    }

    result_hash_map
}

#[test]
fn test_read_abi_simple_contract() {
    let path_a = PathBuf::from(r"starknet_programs/fibonacci_abi.json");
    // using the function to read an abi
    let result = read_abi(&path_a);

    // this is the expected result of the function above
    let expected_result: HashMap<String, (usize, EntryPointType)> =
        HashMap::from([(String::from("fib"), (0_usize, EntryPointType::External))]);

    // final check
    assert_eq!(result, expected_result)
}

#[test]
fn test_read_abi_complex_contract() {
    let path_a = PathBuf::from(r"starknet_programs/constructor_abi.json");

    let result = read_abi(&path_a);

    // this is the expected result of the function above

    let expected_result: HashMap<String, (usize, EntryPointType)> = HashMap::from([
        (
            String::from("constructor"),
            (0_usize, EntryPointType::Constructor),
        ),
        (
            String::from("get_owner"),
            (0_usize, EntryPointType::External),
        ),
    ]);

    // final check
    assert_eq!(result, expected_result)
}

#[test]
fn test_read_abi_with_l1_handler_and_multiple_functions() {
    let path_a = PathBuf::from(r"starknet_programs/l1l2_abi.json");

    let result = read_abi(&path_a);

    // this is the expected result of the function above

    let expected_result: HashMap<String, (usize, EntryPointType)> = HashMap::from([
        (
            String::from("increase_balance"),
            (1_usize, EntryPointType::External),
        ),
        (
            String::from("withdraw"),
            (2_usize, EntryPointType::External),
        ),
        (
            String::from("get_balance"),
            (0_usize, EntryPointType::External),
        ),
        (
            String::from("deposit"),
            (0_usize, EntryPointType::L1Handler),
        ),
    ]);

    // final check
    assert_eq!(result, expected_result)
}
