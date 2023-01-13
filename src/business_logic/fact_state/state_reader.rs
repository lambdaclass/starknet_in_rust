use std::collections::HashMap;

use felt::Felt;

use crate::{core::errors::state_errors::StateError, starknet_storage::storage::Storage};

use super::contract_state::ContractState;

pub(crate) struct StateReader<S1: Storage, S2: Storage> {
    global_state_root: HashMap<Felt, [u8; 32]>,
    ffc: S1,
    contract_states: HashMap<Felt, ContractState>,
    contract_class_storage: S2,
}

impl<S1: Storage, S2: Storage> StateReader<S1, S2> {
    pub(crate) fn new(
        global_state_root: HashMap<Felt, [u8; 32]>,
        ffc: S1,
        contract_class_storage: S2,
    ) -> Self {
        Self {
            global_state_root,
            ffc,
            contract_states: HashMap::new(),
            contract_class_storage,
        }
    }

    pub(crate) fn get_class_hash_at(
        &self,
        contract_address: &Felt,
    ) -> Result<&ContractState, StateError> {
        if !self.contract_states.contains_key(contract_address) {
            let key = self.global_state_root.get(contract_address).unwrap();
            let result = self.ffc.get_value_or_fail(key).unwrap();
            todo!()
        }

        Ok(self.contract_states.get(contract_address).unwrap())
    }
}
