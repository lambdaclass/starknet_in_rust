use felt::Felt;
use thiserror::Error;

use crate::{
    business_logic::{fact_state::contract_state::ContractState, state::state_cache::StorageEntry},
    services::api::contract_class_errors::ContractClassError,
    starknet_storage::errors::storage_errors::StorageError,
    utils::Address,
};

#[derive(Debug, PartialEq, Error)]
pub enum UtilsError {
    #[error("Couldn't convert Felt: {0} to [u8;32]")]
    FeltToFixBytesArrayFail(Felt),
}
