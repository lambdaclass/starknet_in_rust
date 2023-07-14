use thiserror::Error;

#[derive(Debug, Error)]
pub enum HashError {
    #[error("Failed to compute hash {0}")]
    FailedToComputeHash(String),
}
