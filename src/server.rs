use std::{collections::HashMap, fs::File, path::PathBuf};

pub fn add_class_hash(class_hash: &String, contract_name: &PathBuf) {
    let file = File::create("class_hash_contract.json").unwrap();
    let class_contract_dict = HashMap::from([(class_hash.clone(), contract_name.clone())]);
    serde_json::to_writer_pretty(file, &class_contract_dict).unwrap();
}

pub fn add_address(address: &String, contract_name: &PathBuf) {
    let file = File::create("address_contract.json").unwrap();
    let address_contract_dict = HashMap::from([(address.clone(), contract_name.clone())]);
    serde_json::to_writer_pretty(file, &address_contract_dict).unwrap();
}

pub fn get_contract_from_class_hash(class_hash: &String) -> PathBuf {
    let file = File::open("class_hash_contract.json").unwrap();
    let class_contract_dict: HashMap<String, PathBuf> = serde_json::from_reader(&file).unwrap();
    class_contract_dict.get(class_hash).unwrap().clone()
}

pub fn get_contract_from_address(address: &String) -> PathBuf {
    let file = File::open("address_contract.json").unwrap();
    let address_contract_dict: HashMap<String, PathBuf> = serde_json::from_reader(&file).unwrap();
    address_contract_dict.get(address).unwrap().clone()
}
