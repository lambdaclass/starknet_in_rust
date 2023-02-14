use felt::Felt;
use thiserror::Error;

#[derive(Debug, PartialEq, Error)]
pub enum UtilsError {
    #[error("Couldn't convert Felt: {0} to [u8;32]")]
    FeltToFixBytesArrayFail(Felt),
}
