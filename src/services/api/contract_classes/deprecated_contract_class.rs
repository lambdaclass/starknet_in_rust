use crate::services::api::contract_class_errors::ContractClassError;
use crate::EntryPointType;
use cairo_vm::felt::Felt252;
use cairo_vm::types::{errors::program_errors::ProgramError, program::Program};
use getset::Getters;
use serde_json::Value;
use starknet_api::deprecated_contract_class::EntryPoint;
use std::collections::HashMap;
use std::io::{BufReader, Read};
use std::path::{Path, PathBuf};

use super::deprecated_parsed_contract_class::{
    to_cairo_runner_program, AbiType, ContractEntryPoint,
};

// -------------------------------
//         Contract Class
// -------------------------------

#[derive(Clone, Debug, Eq, Getters, PartialEq)]
pub struct ContractClass {
    #[getset(get = "pub")]
    pub(crate) program: Program,
    #[getset(get = "pub")]
    pub(crate) program_json: serde_json::Value,
    #[getset(get = "pub")]
    pub(crate) entry_points_by_type: HashMap<EntryPointType, Vec<ContractEntryPoint>>,
    #[getset(get = "pub")]
    pub(crate) abi: Option<AbiType>,
}

impl ContractClass {
    pub fn new(
        program_json: Value,
        program: Program,
        entry_points_by_type: HashMap<EntryPointType, Vec<ContractEntryPoint>>,
        abi: Option<AbiType>,
    ) -> Result<Self, ContractClassError> {
        for entry_points in entry_points_by_type.values() {
            for i in 1..entry_points.len() {
                if entry_points[i - 1].selector() > entry_points[i].selector() {
                    return Err(ContractClassError::EntrypointError(entry_points.clone()));
                }
            }
        }

        Ok(ContractClass {
            program_json,
            program,
            entry_points_by_type,
            abi,
        })
    }

    pub fn new_from_path<F>(path: F) -> Result<Self, ProgramError>
    where
        F: AsRef<Path>,
    {
        Self::try_from(std::fs::read_to_string(path)?.as_str())
    }
}

// -------------------------------
//         From traits
// -------------------------------

impl TryFrom<&str> for ContractClass {
    type Error = ProgramError;

    fn try_from(s: &str) -> Result<Self, ProgramError> {
        let contract_class: starknet_api::deprecated_contract_class::ContractClass =
            serde_json::from_str(s)?;
        let program = to_cairo_runner_program(&contract_class.program)?;
        let entry_points_by_type =
            convert_entry_points(contract_class.clone().entry_points_by_type);
        let program_json = serde_json::from_str(s)?;
        Ok(ContractClass {
            program_json,
            program,
            entry_points_by_type,
            abi: contract_class.abi,
        })
    }
}

impl TryFrom<&Path> for ContractClass {
    type Error = ProgramError;

    fn try_from(path: &Path) -> Result<Self, Self::Error> {
        Self::new_from_path(path)
    }
}

impl TryFrom<PathBuf> for ContractClass {
    type Error = ProgramError;

    fn try_from(path: PathBuf) -> Result<Self, Self::Error> {
        Self::new_from_path(path)
    }
}

impl TryFrom<&PathBuf> for ContractClass {
    type Error = ProgramError;

    fn try_from(path: &PathBuf) -> Result<Self, Self::Error> {
        Self::new_from_path(path)
    }
}

impl<T: std::io::Read> TryFrom<BufReader<T>> for ContractClass {
    type Error = ProgramError;

    fn try_from(mut reader: BufReader<T>) -> Result<Self, Self::Error> {
        let mut s = String::new();
        reader.read_to_string(&mut s)?;
        Self::try_from(s.as_str())
    }
}

// -------------------
//  Helper Functions
// -------------------

fn convert_entry_points(
    entry_points: HashMap<starknet_api::deprecated_contract_class::EntryPointType, Vec<EntryPoint>>,
) -> HashMap<EntryPointType, Vec<ContractEntryPoint>> {
    let mut converted_entries: HashMap<EntryPointType, Vec<ContractEntryPoint>> = HashMap::new();
    for (entry_type, entry_points) in entry_points {
        let en_type = entry_type.into();

        let contracts_entry_points = entry_points
            .into_iter()
            .map(|e| {
                let selector = Felt252::from_bytes_be(e.selector.0.bytes());
                let offset = e.offset.0;
                ContractEntryPoint::new(selector, offset)
            })
            .collect::<Vec<ContractEntryPoint>>();

        converted_entries.insert(en_type, contracts_entry_points);
    }

    converted_entries
}

#[cfg(test)]
mod tests {
    use crate::core::contract_address::compute_deprecated_class_hash;

    use super::*;
    use crate::services::api::contract_classes::deprecated_parsed_contract_class::ParsedContractClass;
    use cairo_vm::{
        felt::{felt_str, PRIME_STR},
        serde::deserialize_program::BuiltinName,
    };
    use std::{fs, str::FromStr};

    #[test]
    fn deserialize_contract_class() {
        // This specific contract compiles with --no_debug_info
        let serialized = fs::read_to_string("starknet_programs/AccountPreset.json")
            .expect("should be able to read file");

        let res = ContractClass::try_from(serialized.as_str());

        assert!(res.is_ok());

        let contract_class = res.unwrap();

        // We check only some of the attributes. Ideally we would serialize
        // and compare with original
        // TODO: add abi.
        // assert_eq!(contract_class.abi(), &None);
        assert_eq!(
            contract_class
                .program()
                .iter_builtins()
                .cloned()
                .collect::<Vec<BuiltinName>>(),
            [
                BuiltinName::pedersen,
                BuiltinName::range_check,
                BuiltinName::ecdsa,
                BuiltinName::bitwise
            ]
        );
        assert_eq!(contract_class.program().prime(), PRIME_STR);
        assert_eq!(
            contract_class
                .entry_points_by_type()
                .get(&EntryPointType::L1Handler)
                .unwrap(),
            &vec![]
        );
        assert_eq!(
            contract_class
                .entry_points_by_type()
                .get(&EntryPointType::Constructor)
                .unwrap(),
            &vec![ContractEntryPoint::new(
                felt_str!(
                    "1159040026212278395030414237414753050475174923702621880048416706425641521556"
                ),
                366
            )]
        );
    }

    #[test]
    fn test_contract_class_new_equals_raw_instantiation() {
        let contract_str = fs::read_to_string("starknet_programs/raw_contract_classes/0x4479c3b883b34f1eafa5065418225d78a11ee7957c371e1b285e4b77afc6dad.json").unwrap();

        let parsed_contract_class = ParsedContractClass::try_from(contract_str.as_str()).unwrap();
        let contract_class = ContractClass {
            program_json: serde_json::Value::from_str(&contract_str).unwrap(),
            program: parsed_contract_class.program.clone(),
            entry_points_by_type: parsed_contract_class.entry_points_by_type.clone(),
            abi: parsed_contract_class.abi.clone(),
        };

        let contract_class_new = ContractClass::new(
            serde_json::Value::from_str(&contract_str).unwrap(),
            parsed_contract_class.program,
            parsed_contract_class.entry_points_by_type,
            parsed_contract_class.abi,
        )
        .unwrap();

        assert_eq!(contract_class, contract_class_new);
    }

    #[test]
    fn test_compute_class_hash_0x4479c3b883b34f1eafa5065418225d78a11ee7957c371e1b285e4b77afc6dad_try_from(
    ) {
        let contract_str = fs::read_to_string("starknet_programs/raw_contract_classes/0x4479c3b883b34f1eafa5065418225d78a11ee7957c371e1b285e4b77afc6dad.json").unwrap();

        let contract_class = ContractClass::try_from(contract_str.as_str()).unwrap();

        assert_eq!(
            compute_deprecated_class_hash(&contract_class).unwrap(),
            felt_str!(
                "4479c3b883b34f1eafa5065418225d78a11ee7957c371e1b285e4b77afc6dad",
                16
            )
        );
    }

    #[test]
    fn test_new_equals_try_from() {
        let contract_str = fs::read_to_string("starknet_programs/raw_contract_classes/0x4479c3b883b34f1eafa5065418225d78a11ee7957c371e1b285e4b77afc6dad.json").unwrap();

        let parsed_contract_class = ParsedContractClass::try_from(contract_str.as_str()).unwrap();

        let contract_class_new = ContractClass::new(
            serde_json::Value::from_str(&contract_str).unwrap(),
            parsed_contract_class.program,
            parsed_contract_class.entry_points_by_type,
            parsed_contract_class.abi,
        )
        .unwrap();

        let contract_class = ContractClass::try_from(contract_str.as_str()).unwrap();

        assert_eq!(contract_class.abi, contract_class_new.abi);
        assert_eq!(contract_class.program, contract_class_new.program);
        assert_eq!(contract_class.program_json, contract_class_new.program_json);
        assert_eq!(
            contract_class.entry_points_by_type,
            contract_class_new.entry_points_by_type
        );
    }

    #[test]
    fn test_compute_class_hash_0x4479c3b883b34f1eafa5065418225d78a11ee7957c371e1b285e4b77afc6dad_new(
    ) {
        let contract_str = fs::read_to_string("starknet_programs/raw_contract_classes/0x4479c3b883b34f1eafa5065418225d78a11ee7957c371e1b285e4b77afc6dad.json").unwrap();

        let parsed_contract_class = ParsedContractClass::try_from(contract_str.as_str()).unwrap();
        let contract_class = ContractClass::new(
            serde_json::Value::from_str(&contract_str).unwrap(),
            parsed_contract_class.program,
            parsed_contract_class.entry_points_by_type,
            parsed_contract_class.abi,
        )
        .unwrap();

        assert_eq!(
            compute_deprecated_class_hash(&contract_class).unwrap(),
            felt_str!(
                "4479c3b883b34f1eafa5065418225d78a11ee7957c371e1b285e4b77afc6dad",
                16
            )
        );
    }

    #[test]
    fn test_compute_class_hash_0x4479c3b883b34f1eafa5065418225d78a11ee7957c371e1b285e4b77afc6dad() {
        let contract_str = fs::read_to_string("starknet_programs/raw_contract_classes/0x4479c3b883b34f1eafa5065418225d78a11ee7957c371e1b285e4b77afc6dad.json").unwrap();

        let parsed_contract_class = ParsedContractClass::try_from(contract_str.as_str()).unwrap();
        let contract_class = ContractClass {
            program_json: serde_json::Value::from_str(&contract_str).unwrap(),
            program: parsed_contract_class.program,
            entry_points_by_type: parsed_contract_class.entry_points_by_type,
            abi: parsed_contract_class.abi,
        };

        assert_eq!(
            compute_deprecated_class_hash(&contract_class).unwrap(),
            felt_str!(
                "4479c3b883b34f1eafa5065418225d78a11ee7957c371e1b285e4b77afc6dad",
                16
            )
        );
    }
}
