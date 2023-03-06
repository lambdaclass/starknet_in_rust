use crate::{
    business_logic::state::cached_state::UNINITIALIZED_CLASS_HASH,
    utils::{Address, ClassHash},
};
use felt::Felt;
use serde::{Deserialize, Serialize};

#[derive(Deserialize, Serialize, PartialEq, Debug, Clone)]
pub struct ContractState {
    pub(crate) class_hash: ClassHash,
    pub(crate) nonce: Felt,
    pub(crate) storage_key: [u8; 32],
    pub(crate) storage_value: Felt,
}

impl ContractState {
    pub fn new(
        class_hash: ClassHash,
        nonce: Felt,
        storage_key: [u8; 32],
        storage_value: Felt,
    ) -> Self {
        Self {
            class_hash,
            nonce,
            storage_key,
            storage_value,
        }
    }

    // TODO: Remove warning inhibitor when finally used.
    #[allow(dead_code)]
    pub(crate) fn empty() -> Self {
        Self {
            class_hash: *UNINITIALIZED_CLASS_HASH,
            nonce: 0.into(),
            storage_key: [0; 32],
            storage_value: Felt::new(0),
        }
    }

    // TODO: Remove warning inhibitor when finally used.
    #[allow(dead_code)]
    fn initialized(&self) -> bool {
        &self.class_hash != UNINITIALIZED_CLASS_HASH
    }

    // TODO: Remove warning inhibitor when finally used.
    #[allow(dead_code)]
    fn is_empty(&self) -> bool {
        !self.initialized()
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct StateSelector {
    pub contract_addresses: Vec<Address>,
    pub class_hashes: Vec<[u8; 32]>,
}
