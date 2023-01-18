use std::collections::HashMap;

use felt::Felt;
use serde::{Deserialize, Serialize};

use crate::{business_logic::state::cached_state::UNINITIALIZED_CLASS_HASH, utils::Address};

#[derive(Deserialize, Serialize, PartialEq, Debug, Clone)]
pub struct ContractState {
    pub(crate) contract_hash: Vec<u8>,
    pub(crate) nonce: Felt,
    pub(crate) storage_keys: HashMap<[u8; 32], Felt>,
}

impl ContractState {
    pub(crate) fn create(
        contract_hash: Vec<u8>,
        nonce: Felt,
        storage_keys: HashMap<[u8; 32], Felt>,
    ) -> Self {
        Self {
            contract_hash,
            nonce,
            storage_keys,
        }
    }

    pub(crate) fn empty() -> Self {
        Self {
            contract_hash: UNINITIALIZED_CLASS_HASH.to_vec(),
            nonce: 0.into(),
            storage_keys: HashMap::new(),
        }
    }

    fn initialized(&self) -> bool {
        self.contract_hash != UNINITIALIZED_CLASS_HASH
    }

    fn is_empty(&self) -> bool {
        !self.initialized()
    }
}
