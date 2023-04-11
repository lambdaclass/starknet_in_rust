use crate::public::abi::AbiType;
use cairo_rs::serde::deserialize_program::BuiltinName;
use cairo_rs::types::errors::program_errors::ProgramError;
use cairo_rs::types::program::Program;
use cairo_rs::utils::is_subsequence;
use serde::Deserialize;
use starknet_contract_class::error::ContractClassError;
use starknet_contract_class::ParsedContractClass;
use std::collections::HashMap;
use std::fs::File;
use std::io::BufReader;
use std::path::PathBuf;

// Reexport starknet-contract-class objects
pub use starknet_contract_class::ContractEntryPoint;
pub use starknet_contract_class::EntryPointType;

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

#[derive(Clone, Debug, Eq, PartialEq, Deserialize)]
#[serde(from = "ParsedContractClass")]
pub struct ContractClass {
    pub program: Program,
    pub entry_points_by_type: HashMap<EntryPointType, Vec<ContractEntryPoint>>,
    pub abi: Option<AbiType>,
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
        if !is_subsequence(&self.program.builtins, &SUPPORTED_BUILTINS) {
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
        let file = File::open(path)?;
        let reader = BufReader::new(file);
        Ok(serde_json::from_reader(reader)?)
    }
}
