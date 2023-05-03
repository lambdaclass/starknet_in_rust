// Reexport starknet-contract-class objects
pub use starknet_contract_class::ContractEntryPoint;
pub use starknet_contract_class::EntryPointType;

use crate::{public::abi::AbiType, services::api::contract_class_errors::ContractClassError};
use cairo_vm::{
    serde::deserialize_program::BuiltinName,
    types::{errors::program_errors::ProgramError, program::Program},
    utils::is_subsequence,
};
use getset::Getters;
use serde::Deserialize;
use starknet_contract_class::ParsedContractClass;
use std::{collections::HashMap, path::PathBuf};

const SUPPORTED_BUILTINS: [BuiltinName; 5] = [
    BuiltinName::pedersen,
    BuiltinName::range_check,
    BuiltinName::ecdsa,
    BuiltinName::bitwise,
    BuiltinName::ec_op,
];

// -------------------------------
//         Contract Class
// -------------------------------

#[derive(Clone, Debug, Eq, Getters, PartialEq, Deserialize)]
#[serde(from = "ParsedContractClass")]
pub struct ContractClass {
    #[getset(get = "pub")]
    pub(crate) program: Program,
    #[getset(get = "pub")]
    pub(crate) entry_points_by_type: HashMap<EntryPointType, Vec<ContractEntryPoint>>,
    #[getset(get = "pub")]
    pub(crate) abi: Option<AbiType>,
}

impl ContractClass {
    pub fn new(
        program: Program,
        entry_points_by_type: HashMap<EntryPointType, Vec<ContractEntryPoint>>,
        abi: Option<AbiType>,
    ) -> Result<Self, ContractClassError> {
        for entry_points in entry_points_by_type.values() {
            let mut index = 1;
            while let Some(entry_point) = entry_points.get(index) {
                if entry_point.selector > entry_points[index - 1].selector {
                    return Err(ContractClassError::EntrypointError(entry_points.clone()));
                }
                index += 1;
            }
        }

        Ok(Self {
            program,
            entry_points_by_type,
            abi,
        })
    }

    pub(crate) fn validate(&self) -> Result<(), ContractClassError> {
        let program_builtins = self
            .program
            .iter_builtins()
            .cloned()
            .collect::<Vec<BuiltinName>>();
        if !is_subsequence(&program_builtins, &SUPPORTED_BUILTINS) {
            return Err(ContractClassError::DisorderedBuiltins);
        };

        Ok(())
    }
}

impl From<ParsedContractClass> for ContractClass {
    fn from(value: ParsedContractClass) -> Self {
        let ParsedContractClass {
            program,
            entry_points_by_type,
            abi,
        } = value;
        Self {
            program,
            entry_points_by_type,
            abi,
        }
    }
}

// -------------------
//  TryFrom traits
// -------------------

impl TryFrom<&str> for ContractClass {
    type Error = ProgramError;

    fn try_from(s: &str) -> Result<Self, ProgramError> {
        Ok(serde_json::from_str(s)?)
    }
}

impl TryFrom<PathBuf> for ContractClass {
    type Error = ProgramError;

    fn try_from(path: PathBuf) -> Result<Self, Self::Error> {
        Self::try_from(&path)
    }
}

impl TryFrom<&PathBuf> for ContractClass {
    type Error = ProgramError;

    fn try_from(path: &PathBuf) -> Result<Self, Self::Error> {
        Ok(ParsedContractClass::try_from(path)?.into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cairo_vm::felt::{felt_str, PRIME_STR};
    use coverage_helper::test;
    use std::{fs::File, io::Read};

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
        assert_eq!(contract_class.abi(), &None);

        let program_builtins = contract_class
            .program()
            .iter_builtins()
            .cloned()
            .collect::<Vec<BuiltinName>>();
        assert_eq!(
            program_builtins,
            vec![
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
            &vec![ContractEntryPoint {
                selector: felt_str!(
                    "1159040026212278395030414237414753050475174923702621880048416706425641521556"
                ),
                offset: 366
            }]
        );
    }
}
