use cairo_rs::vm::errors::memory_errors::MemoryError;
use thiserror::Error;

#[derive(Debug, PartialEq, Error)]
pub enum StarknetRunnerError {
    #[error("Maybe relocatable should be a Felt")]
    NotAFelt,
    #[error("Maybe relocatable should be a Relocatable")]
    NotARelocatable,
    #[error("could not convert Felt to usize")]
    DataConvertionError,
    #[error(transparent)]
    MemoryException(#[from] MemoryError),
}
