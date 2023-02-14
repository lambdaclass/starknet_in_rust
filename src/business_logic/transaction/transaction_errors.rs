use felt::Felt;
use thiserror::Error;

#[derive(Debug, PartialEq, Error)]
pub enum TransactionError {
    #[error("Invalid transaction version {0}")]
    InvalidTransactionVersion(u64),
    #[error("The entry_point_selector must be 617075754465154585683856897856256838130216341506379215893724690153393808813, found {0:?}")]
    UnauthorizedEntryPointForInvoke(Felt),
    #[error("Calling other contracts during validate execution is forbidden")]
    UnauthorizedActionOnValidate,
    #[error("Error ExecutionEntryPoint")]
    ExecutionEntryPointError,
}
