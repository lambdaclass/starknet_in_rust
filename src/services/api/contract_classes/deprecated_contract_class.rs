use crate::services::api::contract_class_errors::ContractClassError;
use cairo_vm::felt::Felt252;
use cairo_vm::types::{errors::program_errors::ProgramError, program::Program};
use getset::Getters;
use lambda_starknet_api::deprecated_contract_class::EntryPoint;
use serde_json::Value;
pub use starknet_contract_class::to_cairo_runner_program;
use starknet_contract_class::AbiType;
use starknet_contract_class::{ContractEntryPoint, EntryPointType};
use std::{collections::HashMap, fs::File, io::BufReader, path::PathBuf};

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
            let mut index = 1;
            while let Some(entry_point) = entry_points.get(index) {
                if entry_point.selector() > entry_points[index - 1].selector() {
                    return Err(ContractClassError::EntrypointError(entry_points.clone()));
                }
                index += 1;
            }
        }

        Ok(ContractClass {
            program_json,
            program,
            entry_points_by_type,
            abi,
        })
    }
}

// -------------------------------
//         From traits
// -------------------------------
impl TryFrom<lambda_starknet_api::deprecated_contract_class::ContractClass> for ContractClass {
    type Error = ProgramError;

    fn try_from(
        contract_class: lambda_starknet_api::deprecated_contract_class::ContractClass,
    ) -> Result<Self, Self::Error> {
        let program = to_cairo_runner_program(&contract_class.program)?;
        let entry_points_by_type =
            convert_entry_points(contract_class.clone().entry_points_by_type);
        let program_json = serde_json::to_value(&contract_class)?;
        Ok(ContractClass {
            program_json,
            program,
            entry_points_by_type,
            abi: contract_class.abi,
        })
    }
}

// -------------------
//  Helper Functions
// -------------------

impl TryFrom<&str> for ContractClass {
    type Error = ProgramError;

    fn try_from(s: &str) -> Result<Self, ProgramError> {
        let raw_contract_class: lambda_starknet_api::deprecated_contract_class::ContractClass =
            serde_json::from_str(s)?;
        ContractClass::try_from(raw_contract_class)
    }
}

impl TryFrom<PathBuf> for ContractClass {
    type Error = ProgramError;

    fn try_from(path: PathBuf) -> Result<Self, Self::Error> {
        ContractClass::try_from(&path)
    }
}

impl TryFrom<&PathBuf> for ContractClass {
    type Error = ProgramError;

    fn try_from(path: &PathBuf) -> Result<Self, Self::Error> {
        let file = File::open(path)?;
        let reader = BufReader::new(file);
        let raw_contract_class: lambda_starknet_api::deprecated_contract_class::ContractClass =
            serde_json::from_reader(reader)?;
        ContractClass::try_from(raw_contract_class)
    }
}

impl<T: std::io::Read> TryFrom<BufReader<T>> for ContractClass {
    type Error = ProgramError;

    fn try_from(reader: BufReader<T>) -> Result<Self, Self::Error> {
        let raw_contract_class: lambda_starknet_api::deprecated_contract_class::ContractClass =
            serde_json::from_reader(reader)?;
        ContractClass::try_from(raw_contract_class)
    }
}

fn convert_entry_points(
    entry_points: HashMap<
        lambda_starknet_api::deprecated_contract_class::EntryPointType,
        Vec<EntryPoint>,
    >,
) -> HashMap<EntryPointType, Vec<ContractEntryPoint>> {
    let mut converted_entries: HashMap<EntryPointType, Vec<ContractEntryPoint>> = HashMap::new();
    for (entry_type, vec) in entry_points {
        let en_type = entry_type.into();

        let contracts_entry_points = vec
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
    use super::*;
    use cairo_vm::{
        felt::{felt_str, PRIME_STR},
        serde::deserialize_program::BuiltinName,
    };
    use std::io::Read;

    #[test]
    fn deserialize_contract_class() {
        let mut serialized = String::new();

        // This specific contract compiles with --no_debug_info
        File::open(PathBuf::from("starknet_programs/AccountPreset.json"))
            .and_then(|mut f| f.read_to_string(&mut serialized))
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
}
