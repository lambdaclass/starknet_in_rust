use thiserror::Error;

use super::contract_classes::contract_class::ContractEntryPoint;

#[derive(Debug, PartialEq, Eq, Error)]
pub enum ContractClassError {
    #[error("Given builtins are not in appropiate order")]
    DisorderedBuiltins,
    #[error("Entry point type not found")]
    NoneEntryPointType,
    #[error("Entry points must be unique and sorted. Found: {0:?}")]
    EntrypointError(Vec<ContractEntryPoint>),
}
