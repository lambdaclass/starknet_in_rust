use crate::{
    business_logic::state::cached_state::UNINITIALIZED_CLASS_HASH,
    utils::{Address, ClassHash},
};
use felt::Felt;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Deserialize, Serialize, PartialEq, Eq, Debug, Clone)]
pub struct ContractState {
    pub(crate) class_hash: ClassHash,
    pub(crate) nonce: Felt,
    pub(crate) storage_keys: HashMap<Felt, Felt>,
}

impl ContractState {
    pub fn new(class_hash: ClassHash, nonce: Felt, storage_keys: HashMap<Felt, Felt>) -> Self {
        Self {
            class_hash,
            nonce,
            storage_keys,
        }
    }

    // TODO: Remove warning inhibitor when finally used.
    #[allow(dead_code)]
    pub(crate) fn empty() -> Self {
        Self {
            class_hash: *UNINITIALIZED_CLASS_HASH,
            nonce: 0.into(),
            storage_keys: HashMap::new(),
        }
    }

    fn initialized(&self) -> bool {
        &self.class_hash != UNINITIALIZED_CLASS_HASH
    }

    // TODO: Remove warning inhibitor when finally used.
    #[allow(dead_code)]
    fn is_empty(&self) -> bool {
        !self.initialized()
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StateSelector {
    pub contract_addresses: Vec<Address>,
    pub class_hashes: Vec<ClassHash>,
}
