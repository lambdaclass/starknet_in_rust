use thiserror::Error;

#[derive(Debug, Error)]
pub enum RpcStateError {
    #[error("Missing .env file")]
    MissingEnvFile,
    #[error("Missing rpc endpoints")]
    MissingRpcEndpoints,
    #[error("RPC call failed with error: {0}")]
    RpcCall(String),
    #[error("Request failed with error: {0}")]
    Request(String),
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    SerdeJson(#[from] serde_json::Error),
    #[error("Object {0} obtained from rpc call has no field {1}")]
    RpcObjectHasNoField(String, String),
    #[error("Failed to convert StarkFelt to PatriciaKey")]
    StarkFeltToParticiaKeyConversion,
    #[error("The service is down")]
    RpcConnectionNotAvailable,
    #[error("The response does not have a field named '{0}'")]
    MissingRpcResponseField(String),
    #[error("Wrong type for response field '{0}'")]
    RpcResponseWrongType(String),
}
