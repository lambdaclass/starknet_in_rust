#![deny(warnings)]

use cairo_vm::felt::{Felt252, PRIME_STR};
use cairo_vm::{
    serde::deserialize_program::{
        deserialize_array_of_bigint_hex, Attribute, BuiltinName, HintParams, Identifier,
        ReferenceManager,
    },
    types::{
        errors::program_errors::ProgramError, program::Program, relocatable::MaybeRelocatable,
    },
};
use getset::{CopyGetters, Getters};
use serde::Deserialize;
use starknet_api::deprecated_contract_class::{ContractClassAbiEntry, EntryPoint};
use std::{collections::HashMap, fs::File, io::BufReader, path::PathBuf};

pub type AbiType = Vec<ContractClassAbiEntry>;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum EntryPointType {
    External,
    L1Handler,
    Constructor,
}

#[derive(Clone, CopyGetters, Debug, Default, Eq, Getters, Hash, PartialEq)]
pub struct ContractEntryPoint {
    #[getset(get = "pub")]
    pub selector: Felt252,
    #[getset(get_copy = "pub")]
    pub offset: usize,
}

impl ContractEntryPoint {
    pub fn new(selector: Felt252, offset: usize) -> ContractEntryPoint {
        ContractEntryPoint { selector, offset }
    }
}

// -------------------------------
//         Contract Class
// -------------------------------

#[derive(Clone, Debug, Eq, PartialEq, Deserialize)]
#[serde(try_from = "starknet_api::deprecated_contract_class::ContractClass")]
pub struct ParsedContractClass {
    pub program: Program,
    pub entry_points_by_type: HashMap<EntryPointType, Vec<ContractEntryPoint>>,
    pub abi: Option<AbiType>,
}

// -------------------------------
//         From traits
// -------------------------------

impl From<&ContractEntryPoint> for Vec<MaybeRelocatable> {
    fn from(entry_point: &ContractEntryPoint) -> Self {
        vec![
            MaybeRelocatable::from(entry_point.selector.clone()),
            MaybeRelocatable::from(entry_point.offset),
        ]
    }
}

impl From<starknet_api::deprecated_contract_class::EntryPointType> for EntryPointType {
    fn from(entry_type: starknet_api::deprecated_contract_class::EntryPointType) -> Self {
        type ApiEPT = starknet_api::deprecated_contract_class::EntryPointType;
        type StarknetEPT = EntryPointType;

        match entry_type {
            ApiEPT::Constructor => StarknetEPT::Constructor,
            ApiEPT::External => StarknetEPT::External,
            ApiEPT::L1Handler => StarknetEPT::L1Handler,
        }
    }
}

impl TryFrom<starknet_api::deprecated_contract_class::ContractClass> for ParsedContractClass {
    type Error = ProgramError;

    fn try_from(
        contract_class: starknet_api::deprecated_contract_class::ContractClass,
    ) -> Result<Self, Self::Error> {
        let program = to_cairo_runner_program(&contract_class.program)?;
        let entry_points_by_type = convert_entry_points(contract_class.entry_points_by_type);
        Ok(Self {
            program,
            entry_points_by_type,
            abi: contract_class.abi,
        })
    }
}

// -------------------
//  Helper Functions
// -------------------

impl TryFrom<&str> for ParsedContractClass {
    type Error = ProgramError;

    fn try_from(s: &str) -> Result<Self, ProgramError> {
        let raw_contract_class: starknet_api::deprecated_contract_class::ContractClass =
            serde_json::from_str(s)?;

        Self::try_from(raw_contract_class)
    }
}

impl TryFrom<PathBuf> for ParsedContractClass {
    type Error = ProgramError;

    fn try_from(path: PathBuf) -> Result<Self, Self::Error> {
        Self::try_from(&path)
    }
}

impl TryFrom<&PathBuf> for ParsedContractClass {
    type Error = ProgramError;

    fn try_from(path: &PathBuf) -> Result<Self, Self::Error> {
        let file = File::open(path)?;
        let reader = BufReader::new(file);
        let raw_contract_class: starknet_api::deprecated_contract_class::ContractClass =
            serde_json::from_reader(reader)?;
        Self::try_from(raw_contract_class)
    }
}

fn convert_entry_points(
    entry_points: HashMap<starknet_api::deprecated_contract_class::EntryPointType, Vec<EntryPoint>>,
) -> HashMap<EntryPointType, Vec<ContractEntryPoint>> {
    let mut converted_entries: HashMap<EntryPointType, Vec<ContractEntryPoint>> = HashMap::new();
    for (entry_type, vec) in entry_points {
        let en_type = entry_type.into();

        let contracts_entry_points = vec
            .into_iter()
            .map(|e| {
                let selector = Felt252::from_bytes_be(e.selector.0.bytes());
                let offset = e.offset.0;
                ContractEntryPoint { selector, offset }
            })
            .collect::<Vec<ContractEntryPoint>>();

        converted_entries.insert(en_type, contracts_entry_points);
    }

    converted_entries
}

pub fn to_cairo_runner_program(
    program: &starknet_api::deprecated_contract_class::Program,
) -> Result<Program, ProgramError> {
    let program = program.clone();
    let identifiers = serde_json::from_value::<HashMap<String, Identifier>>(program.identifiers)?;

    if program.prime != *PRIME_STR {
        return Err(ProgramError::PrimeDiffers(program.prime.to_string()));
    };

    let error_message_attributes = serde_json::from_value::<Vec<Attribute>>(program.attributes)
        .unwrap_or(Vec::new())
        .into_iter()
        .filter(|attr| attr.name == "error_message")
        .collect();

    let program = Program::new(
        serde_json::from_value::<Vec<BuiltinName>>(program.builtins)?,
        deserialize_array_of_bigint_hex(program.data)?,
        None,
        serde_json::from_value::<HashMap<usize, Vec<HintParams>>>(program.hints)?,
        serde_json::from_value::<ReferenceManager>(program.reference_manager)?,
        identifiers,
        error_message_attributes,
        None,
    )?;

    Ok(program)
}

#[cfg(test)]
mod tests {
    use super::*;
    use cairo_vm::felt::felt_str;
    use starknet_api::deprecated_contract_class::{
        ContractClassAbiEntry, FunctionAbiEntry, FunctionAbiEntryType, FunctionAbiEntryWithType,
        TypedParameter,
    };
    use std::io::Read;

    #[test]
    fn try_from_string_abi() {
        let mut serialized = String::new();

        // This specific contract compiles with --no_debug_info
        File::open(PathBuf::from("../../starknet_programs/fibonacci.json"))
            .and_then(|mut f| f.read_to_string(&mut serialized))
            .expect("should be able to read file");

        let res = ParsedContractClass::try_from(serialized.as_str());

        let contract_class = res.unwrap();

        let expected_abi = Some(vec![ContractClassAbiEntry::Function(
            FunctionAbiEntryWithType {
                r#type: FunctionAbiEntryType::Function,
                entry: FunctionAbiEntry {
                    name: "fib".to_string(),
                    inputs: vec![
                        TypedParameter {
                            name: "first_element".to_string(),
                            r#type: "felt".to_string(),
                        },
                        TypedParameter {
                            name: "second_element".to_string(),
                            r#type: "felt".to_string(),
                        },
                        TypedParameter {
                            name: "n".to_string(),
                            r#type: "felt".to_string(),
                        },
                    ],
                    outputs: vec![TypedParameter {
                        name: "res".to_string(),
                        r#type: "felt".to_string(),
                    }],
                },
            },
        )]);
        assert_eq!(contract_class.abi, expected_abi);
    }

    #[test]
    fn try_from_string() {
        let mut serialized = String::new();

        // This specific contract compiles with --no_debug_info
        File::open(PathBuf::from("../../starknet_programs/AccountPreset.json"))
            .and_then(|mut f| f.read_to_string(&mut serialized))
            .expect("should be able to read file");

        let res = ParsedContractClass::try_from(serialized.as_str());

        let contract_class = res.unwrap();

        let program_builtins: Vec<BuiltinName> =
            contract_class.program.iter_builtins().cloned().collect();
        assert_eq!(
            program_builtins,
            vec![
                BuiltinName::pedersen,
                BuiltinName::range_check,
                BuiltinName::ecdsa,
                BuiltinName::bitwise
            ]
        );
        assert_eq!(
            contract_class
                .entry_points_by_type
                .get(&EntryPointType::L1Handler)
                .unwrap(),
            &vec![]
        );
        assert_eq!(
            contract_class
                .entry_points_by_type
                .get(&EntryPointType::Constructor)
                .unwrap(),
            &vec![ContractEntryPoint {
                selector: felt_str!(
                    "1159040026212278395030414237414753050475174923702621880048416706425641521556"
                ),
                offset: 366
            }]
        );
    }

    #[test]
    fn try_from_string_without_program_attributes() {
        let mut serialized = String::new();

        // This specific contract was extracted from: https://testnet.starkscan.co/class/0x068dd0dd8a54ebdaa10563fbe193e6be1e0f7c423c0c3ce1e91c0b682a86b5f9
        File::open(PathBuf::from(
            "../../starknet_programs/program_without_attributes.json",
        ))
        .and_then(|mut f| f.read_to_string(&mut serialized))
        .expect("should be able to read file");

        let res = ParsedContractClass::try_from(serialized.as_str());

        res.unwrap();
    }

    #[test]
    fn try_from_string_without_program_attributes_2() {
        let mut serialized = String::new();

        // This specific contract was extracted from: https://testnet.starkscan.co/class/0x071b7f73b5e2b4f81f7cf01d4d1569ccba2921b3fa3170cf11cff3720dfe918e
        File::open(PathBuf::from(
            "../../starknet_programs/program_without_attributes_2.json",
        ))
        .and_then(|mut f| f.read_to_string(&mut serialized))
        .expect("should be able to read file");

        let res = ParsedContractClass::try_from(serialized.as_str());

        res.unwrap();
    }

    #[test]
    fn deserialize_equals_try_from() {
        let mut serialized = String::new();

        // This specific contract compiles with --no_debug_info
        File::open(PathBuf::from("../../starknet_programs/AccountPreset.json"))
            .and_then(|mut f| f.read_to_string(&mut serialized))
            .expect("should be able to read file");

        let result_try_from = ParsedContractClass::try_from(serialized.as_str()).unwrap();
        let result_deserialize = serde_json::from_str(&serialized).unwrap();

        assert_eq!(result_try_from, result_deserialize);
    }
}
