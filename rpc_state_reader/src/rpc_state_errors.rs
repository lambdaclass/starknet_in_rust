use thiserror::Error;

#[derive(Debug, Error)]
pub enum RpcStateError {
    #[error("Missing .env file")]
    MissingEnvFile,
    #[error("Missing infura api key")]
    MissingInfuraApiKey,
    #[error(transparent)]
    Rpc(#[from] RpcError),
    #[error(transparent)]
    SerdeJson(#[from] serde_json::Error),
    #[error("Object {0} obtained from rpc call has no field {1}")]
    RpcObjectHasNoField(String, String),
    #[error("Failed to convert StarkFelt to PatriciaKey")]
    StarkFeltToParticiaKeyConversion,
}

#[derive(Error, Debug)]
pub enum RpcError {
    #[error("RPC call failed with error: {0}")]
    RpcCall(String),
    #[error("Request failed with error: {0}")]
    Request(String),
    #[error(transparent)]
    Io(#[from] std::io::Error),
}
