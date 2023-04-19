#![deny(warnings)]

use cairo_felt::{Felt252, PRIME_STR};
use cairo_vm::{
    serde::deserialize_program::{
        deserialize_array_of_bigint_hex, Attribute, BuiltinName, HintParams, Identifier,
        ReferenceManager,
    },
    types::{
        errors::program_errors::ProgramError, program::Program, relocatable::MaybeRelocatable,
    },
};
use serde::Deserialize;
use starknet_api::state::{ContractClassAbiEntry, EntryPoint};
use std::{collections::HashMap, fs::File, io::BufReader, path::PathBuf};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum EntryPointType {
    External,
    L1Handler,
    Constructor,
}

#[derive(Clone, Debug, Default, Eq, Hash, PartialEq)]
pub struct ContractEntryPoint {
    pub selector: Felt252,
    pub offset: usize,
}

pub type AbiType = Vec<HashMap<String, ContractClassAbiEntry>>;

// -------------------------------
//         Contract Class
// -------------------------------

#[derive(Clone, Debug, Eq, PartialEq, Deserialize)]
#[serde(try_from = "starknet_api::state::ContractClass")]
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

impl From<starknet_api::state::EntryPointType> for EntryPointType {
    fn from(entry_type: starknet_api::state::EntryPointType) -> Self {
        type ApiEPT = starknet_api::state::EntryPointType;
        type StarknetEPT = EntryPointType;

        match entry_type {
            ApiEPT::Constructor => StarknetEPT::Constructor,
            ApiEPT::External => StarknetEPT::External,
            ApiEPT::L1Handler => StarknetEPT::L1Handler,
        }
    }
}

impl TryFrom<starknet_api::state::ContractClass> for ParsedContractClass {
    type Error = ProgramError;

    fn try_from(contract_class: starknet_api::state::ContractClass) -> Result<Self, Self::Error> {
        let program = to_cairo_runner_program(&contract_class.program)?;
        let entry_points_by_type = convert_entry_points(contract_class.entry_points_by_type);

        Ok(Self {
            program,
            entry_points_by_type,
            abi: None,
        })
    }
}

// -------------------
//  Helper Functions
// -------------------

impl TryFrom<&str> for ParsedContractClass {
    type Error = ProgramError;

    fn try_from(s: &str) -> Result<Self, ProgramError> {
        let raw_contract_class: starknet_api::state::ContractClass = serde_json::from_str(s)?;
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
        let raw_contract_class: starknet_api::state::ContractClass =
            serde_json::from_reader(reader)?;
        Self::try_from(raw_contract_class)
    }
}

fn convert_entry_points(
    entry_points: HashMap<starknet_api::state::EntryPointType, Vec<EntryPoint>>,
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
    program: &starknet_api::state::Program,
) -> Result<Program, ProgramError> {
    let program = program.clone();
    let identifiers = serde_json::from_value::<HashMap<String, Identifier>>(program.identifiers)?;

    let start = match identifiers.get("__main__.__start__") {
        Some(identifier) => identifier.pc,
        None => None,
    };
    let end = match identifiers.get("__main__.__end__") {
        Some(identifier) => identifier.pc,
        None => None,
    };
    if program.prime != *PRIME_STR {
        return Err(ProgramError::PrimeDiffers(program.prime.to_string()));
    };

    Ok(Program {
        builtins: serde_json::from_value::<Vec<BuiltinName>>(program.builtins)?,
        prime: PRIME_STR.to_string(),
        data: deserialize_array_of_bigint_hex(program.data)?,
        constants: {
            let mut constants = HashMap::new();
            for (key, value) in identifiers.iter() {
                if value.type_.as_deref() == Some("const") {
                    let value = value
                        .value
                        .clone()
                        .ok_or_else(|| ProgramError::ConstWithoutValue(key.to_owned()))?;
                    constants.insert(key.to_owned(), value);
                }
            }

            constants
        },
        main: None,
        start,
        end,
        hints: serde_json::from_value::<HashMap<usize, Vec<HintParams>>>(program.hints)?,
        reference_manager: serde_json::from_value::<ReferenceManager>(program.reference_manager)?,
        identifiers,
        error_message_attributes: serde_json::from_value::<Vec<Attribute>>(program.attributes)?
            .into_iter()
            .filter(|attr| attr.name == "error_message")
            .collect(),
        instruction_locations: None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use cairo_felt::felt_str;
    use std::io::Read;

    #[test]
    fn try_from_string() {
        let mut serialized = String::new();

        // This specific contract compiles with --no_debug_info
        File::open(PathBuf::from("../../starknet_programs/AccountPreset.json"))
            .and_then(|mut f| f.read_to_string(&mut serialized))
            .expect("should be able to read file");

        let res = ParsedContractClass::try_from(serialized.as_str());

        assert!(res.is_ok());

        let contract_class = res.unwrap();

        // We check only some of the attributes. Ideally we would serialize
        // and compare with original
        assert_eq!(contract_class.abi, None);
        assert_eq!(
            contract_class.program.builtins,
            vec![
                BuiltinName::pedersen,
                BuiltinName::range_check,
                BuiltinName::ecdsa,
                BuiltinName::bitwise
            ]
        );
        assert_eq!(contract_class.program.prime, PRIME_STR);
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
    fn deserialize_equals_try_from() {
        let mut serialized = String::new();

        // This specific contract compiles with --no_debug_info
        File::open(PathBuf::from("../../starknet_programs/AccountPreset.json"))
            .and_then(|mut f| f.read_to_string(&mut serialized))
            .expect("should be able to read file");

        let result_try_from = ParsedContractClass::try_from(serialized.as_str());
        let result_deserialize = serde_json::from_str(&serialized);

        assert!(result_try_from.is_ok());
        assert!(result_deserialize.is_ok());

        assert_eq!(result_try_from.unwrap(), result_deserialize.unwrap());
    }
}
