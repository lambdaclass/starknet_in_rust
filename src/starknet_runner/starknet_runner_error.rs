use thiserror::Error;

#[derive(Debug, PartialEq, Error)]
pub enum StarknetRunnerError {
    #[error("Maybe relocatable should be a Felt")]
    NotFeltInReturnValue,
    #[error("Range-check validation failed, number is out of valid range")]
    NumOutOfBounds,
}
