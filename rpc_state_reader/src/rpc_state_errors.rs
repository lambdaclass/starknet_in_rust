use thiserror::Error;

#[derive(Debug, Error)]
pub enum RpcStateError {
    #[error("Missing .env file")]
    MissingEnvFile,
    #[error("Missing infura api key")]
    MissingInfuraApiKey,
}
