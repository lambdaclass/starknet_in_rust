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

pub fn read_abi(abi_name: &PathBuf) -> HashMap<String, usize> {
    let abi: Vec<Signature> = serde_json::from_reader(&File::open(abi_name).unwrap()).unwrap();
    let mut func_type_counter: HashMap<String, usize> = HashMap::new();
    let mut result_hash_map: HashMap<String, usize> = HashMap::new();

    for function in abi {
        let function_address = match func_type_counter.get(&function.type_name) {
            Some(number) => number + 1,
            None => 0,
        };

        func_type_counter.insert(function.type_name, function_address);
        result_hash_map.insert(function.name, function_address);
    }

    result_hash_map
}
