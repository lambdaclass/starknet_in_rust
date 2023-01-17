use std::collections::HashMap;

use felt::Felt;

use crate::{
    core::errors::state_errors::StateError,
    services::api::contract_class::ContractClass,
    starknet_storage::{dict_storage::Prefix, storage::Storage},
    utils::Address,
};

use super::contract_state::{self, ContractState};

pub(crate) struct StateReader<S1: Storage, S2: Storage> {
    global_state_root: HashMap<Address, [u8; 32]>,
    ffc: S1,
    contract_states: HashMap<Address, ContractState>,
    contract_class_storage: S2,
}

impl<S1: Storage, S2: Storage> StateReader<S1, S2> {
    pub(crate) fn new(
        global_state_root: HashMap<Address, [u8; 32]>,
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

    pub(crate) fn get_contract_class(
        &self,
        class_hash: &[u8; 32],
    ) -> Result<ContractClass, StateError> {
        let contract_class = self.contract_class_storage.get_contract_class(class_hash)?;
        contract_class.validate()?;
        Ok(contract_class)
    }

    fn get_contract_state(
        &mut self,
        contract_address: &Address,
    ) -> Result<&ContractState, StateError> {
        if !self.contract_states.contains_key(contract_address) {
            let key = self
                .global_state_root
                .get(contract_address)
                .ok_or_else(|| StateError::NoneContractState(contract_address.clone()))?;
            let result = self.ffc.get_contract_state(key)?;
            self.contract_states
                .insert(contract_address.clone(), result);
        }

        self.contract_states
            .get(contract_address)
            .ok_or_else(|| StateError::NoneContractState(contract_address.clone()))
    }

    pub(crate) fn get_class_hash_at(
        &mut self,
        contract_address: &Address,
    ) -> Result<&Vec<u8>, StateError> {
        Ok(&self.get_contract_state(contract_address)?.contract_hash)
    }

    pub(crate) fn get_nonce_at(&mut self, contract_address: &Address) -> Result<&Felt, StateError> {
        Ok(&self.get_contract_state(contract_address)?.nonce)
    }
}

#[cfg(test)]
mod tests {
    use cairo_rs::types::program::Program;
    use felt::NewFelt;

    use crate::{
        services::api::contract_class::{self, ContractEntryPoint, EntryPointType},
        starknet_storage::dict_storage::DictStorage,
    };

    use super::*;

    #[test]
    fn get_contract_state_test() {
        let mut state_reader =
            StateReader::new(HashMap::new(), DictStorage::new(), DictStorage::new());

        let contract_address = Address(32123.into());
        let contract_state = ContractState::create(vec![1, 2, 3], Felt::new(109));

        state_reader
            .global_state_root
            .insert(contract_address.clone(), [0; 32]);
        state_reader
            .ffc
            .set_contract_state(&[0; 32], &contract_state);

        assert_eq!(
            state_reader.get_contract_state(&contract_address),
            Ok(&contract_state)
        );
        assert_eq!(
            state_reader.get_class_hash_at(&contract_address),
            Ok(&contract_state.contract_hash)
        );
        assert_eq!(
            state_reader.get_nonce_at(&contract_address),
            Ok(&contract_state.nonce)
        );
        assert_eq!(
            state_reader.contract_states,
            HashMap::from([(contract_address, contract_state)])
        );
    }

    #[test]
    fn get_contract_class_test() {
        let mut state_reader =
            StateReader::new(HashMap::new(), DictStorage::new(), DictStorage::new());

        let contract_class_key = [0; 32];
        let contract_class = ContractClass::new(
            Program::default(),
            HashMap::from([(
                EntryPointType::Constructor,
                vec![ContractEntryPoint::default()],
            )]),
            None,
        )
        .expect("Error creating contract class");

        state_reader
            .contract_class_storage
            .set_contract_class(&[0; 32], &contract_class);

        assert_eq!(
            state_reader.get_contract_class(&contract_class_key),
            Ok(contract_class)
        );
    }
}
