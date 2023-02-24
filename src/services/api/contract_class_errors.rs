use super::contract_class::ContractEntryPoint;
use thiserror::Error;

#[derive(Debug, PartialEq, Error)]
pub enum ContractClassError {
    #[error("A contract may have at most 1 constructor")]
    MultipleConstructors,
    #[error("The contract is missing constructor endpoints. Wrong compiler version?")]
    MissingConstractorEndpoint,
    #[error("Given builtins are not in appropiate order")]
    DisorderedBuiltins,
    #[error("Entry point type not found")]
    NoneEntryPointType,
    #[error("Invalid value for field prime: {0}. Expected: {1}.")]
    InvalidPrime(String, String),
    #[error("Entry points must be unique and sorted. Found: {0:?}")]
    EntrypointError(Vec<ContractEntryPoint>),
}
