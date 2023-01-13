use felt::Felt;

use crate::business_logic::state::cached_state::UNINITIALIZED_CLASS_HASH;

pub(crate) struct ContractState {
    contract_hash: Vec<u8>,
    nonce: Felt,
}

impl ContractState {
    fn create(contract_hash: Vec<u8>, nonce: Felt) -> Self {
        Self {
            contract_hash,
            nonce,
        }
    }

    pub(crate) fn empty() -> Self {
        Self {
            contract_hash: UNINITIALIZED_CLASS_HASH.to_vec(),
            nonce: 0.into(),
        }
    }

    fn initialized(&self) -> bool {
        self.contract_hash != UNINITIALIZED_CLASS_HASH
    }

    fn is_empty(&self) -> bool {
        !self.initialized()
    }
}
