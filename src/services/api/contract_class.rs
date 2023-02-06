use std::collections::HashMap;

use cairo_rs::{
    types::{program::Program, relocatable::MaybeRelocatable},
    utils::is_subsequence,
};
use felt::{Felt, PRIME_STR};

use crate::{core::errors::state_errors::StateError, public::abi::AbiType};
use serde::{Deserialize, Serialize};

use super::contract_class_errors::ContractClassError;

pub(crate) const SUPPORTED_BUILTINS: [&str; 5] =
    ["pedersen", "range_check", "ecdsa", "bitwise", "ec_op"];

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Hash)]
pub enum EntryPointType {
    External,
    L1Handler,
    Constructor,
}

#[derive(Debug, Clone, Serialize, Deserialize, Hash, Default, PartialEq)]
pub struct ContractEntryPoint {
    pub(crate) selector: Felt,
    pub(crate) offset: Felt,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ContractClass {
    pub(crate) program: Program,
    pub(crate) entry_points_by_type: HashMap<EntryPointType, Vec<ContractEntryPoint>>,
    pub(crate) abi: Option<AbiType>,
}

impl From<&ContractEntryPoint> for Vec<MaybeRelocatable> {
    fn from(entry_point: &ContractEntryPoint) -> Self {
        vec![
            MaybeRelocatable::from(entry_point.selector.clone()),
            MaybeRelocatable::from(entry_point.offset.clone()),
        ]
    }
}

impl ContractClass {
    pub(crate) fn new(
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

        Ok(ContractClass {
            program,
            entry_points_by_type,
            abi,
        })
    }

    pub(crate) fn validate(&self) -> Result<(), ContractClassError> {
        let supported_builtins: Vec<String> = SUPPORTED_BUILTINS
            .into_iter()
            .map(|s| s.to_string())
            .collect();
        if !is_subsequence(&self.program.builtins, &supported_builtins) {
            return Err(ContractClassError::DisorderedBuiltins);
        };

        if self.program.prime != *PRIME_STR {
            return Err(ContractClassError::InvalidPrime(
                self.program.prime.clone(),
                PRIME_STR.to_string(),
            ));
        };
        Ok(())
    }
}
