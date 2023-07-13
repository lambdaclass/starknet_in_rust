use thiserror::Error;

#[derive(Debug, Error)]
pub enum HashError {
    #[error("Failed to compute hash")]
    FailedToComputeHash,
}
