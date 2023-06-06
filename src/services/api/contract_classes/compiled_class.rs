use crate::services::api::contract_class_errors::ContractClassError;

use super::deprecated_contract_class::ContractClass;
use cairo_lang_starknet::casm_contract_class::CasmContractClass;

#[derive(Clone, PartialEq, Eq, Debug)]
pub enum CompiledClass {
    Deprecated(Box<ContractClass>),
    Casm(Box<CasmContractClass>),
}

impl TryInto<CasmContractClass> for CompiledClass {
    type Error = ContractClassError;
    fn try_into(self) -> Result<CasmContractClass, ContractClassError> {
        match self {
            CompiledClass::Casm(boxed) => Ok(*boxed),
            _ => Err(ContractClassError::NotACasmContractClass),
        }
    }
}

impl TryInto<ContractClass> for CompiledClass {
    type Error = ContractClassError;
    fn try_into(self) -> Result<ContractClass, ContractClassError> {
        match self {
            CompiledClass::Deprecated(boxed) => Ok(*boxed),
            _ => Err(ContractClassError::NotADeprecatedContractClass),
        }
    }
}
