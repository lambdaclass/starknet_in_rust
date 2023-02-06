use thiserror::Error;

#[derive(Debug, Error)]

pub(crate) enum StarknetChainIdError {
    #[error("could not convert chain id to [u8;8]")]
    ConversionErrorToBytes,
}
