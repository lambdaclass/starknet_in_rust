use std::{collections::HashMap, fs::File, path::PathBuf};

pub fn add_class_hash(class_hash: &String, contract_name: &PathBuf) {
    match File::open("class_hash_contract.json") {
        Ok(file) => {
            let mut class_contract_dict: HashMap<String, PathBuf> =
                serde_json::from_reader(&file).unwrap();
            if !class_contract_dict.contains_key(class_hash) {
                class_contract_dict.insert(class_hash.clone(), contract_name.clone());
                serde_json::to_writer_pretty(file, &class_contract_dict).unwrap();
            }
        }
        Err(_) => {
            let file = File::create("class_hash_contract.json").unwrap();
            let class_contract_dict = HashMap::from([(class_hash.clone(), contract_name.clone())]);
            serde_json::to_writer_pretty(file, &class_contract_dict).unwrap();
        }
    }
}

pub fn retrieve_contract_name(class_hash: &String) -> PathBuf {
    let file = File::open("class_hash_contract.json").unwrap();
    let class_contract_dict: HashMap<String, PathBuf> = serde_json::from_reader(&file).unwrap();
    class_contract_dict.get(class_hash).unwrap().clone()
}
