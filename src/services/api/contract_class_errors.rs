use crate::services::api::contract_classes::deprecated_parsed_contract_class::ContractEntryPoint;
use thiserror::Error;

#[derive(Debug, PartialEq, Eq, Error)]
pub enum ContractClassError {
    #[error("Given builtins are not in appropiate order")]
    DisorderedBuiltins,
    #[error("Entry point type not found")]
    NoneEntryPointType,
    #[error("Entry points must be unique and sorted. Found: {0:?}")]
    EntrypointError(Vec<ContractEntryPoint>),
    #[error("Not a casm contract class")]
    NotACasmContractClass,
    #[error("Not a deprecated contract class")]
    NotADeprecatedContractClass,
}
