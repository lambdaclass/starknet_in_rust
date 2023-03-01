use crate::{business_logic::state::cached_state::UNINITIALIZED_CLASS_HASH, utils::Address};
use felt::Felt;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Deserialize, Serialize, PartialEq, Debug, Clone)]
pub struct ContractState {
    pub(crate) contract_hash: [u8; 32],
    pub(crate) nonce: Felt,
    pub(crate) storage_keys: HashMap<Felt, Felt>,
}

impl ContractState {
    pub fn new(contract_hash: [u8; 32], nonce: Felt, storage_keys: HashMap<Felt, Felt>) -> Self {
        Self {
            contract_hash,
            nonce,
            storage_keys,
        }
    }

    // TODO: Remove warning inhibitor when finally used.
    #[allow(dead_code)]
    pub(crate) fn empty() -> Self {
        Self {
            contract_hash: *UNINITIALIZED_CLASS_HASH,
            nonce: 0.into(),
            storage_keys: HashMap::new(),
        }
    }

    // TODO: Remove warning inhibitor when finally used.
    #[allow(dead_code)]
    fn initialized(&self) -> bool {
        &self.contract_hash != UNINITIALIZED_CLASS_HASH
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
