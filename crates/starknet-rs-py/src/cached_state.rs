use crate::types::contract_class::PyContractClass;
use cairo_felt::Felt252;
use num_bigint::BigUint;
use pyo3::{exceptions::PyRuntimeError, prelude::*};
use starknet_rs::{
    business_logic::{
        fact_state::in_memory_state_reader::InMemoryStateReader,
        state::{
            cached_state::CachedState as InnerCachedState,
            state_api::{State, StateReader},
        },
    },
    utils::{felt_to_hash, Address},
};

#[pyclass]
#[pyo3(name = "CachedState")]
#[derive(Debug)]
pub struct PyCachedState {
    state: InnerCachedState<InMemoryStateReader>,
}

#[pymethods]
impl PyCachedState {
    fn get_class_hash_at(&mut self, address: BigUint) -> PyResult<BigUint> {
        Ok(BigUint::from_bytes_be(
            self.state
                .get_class_hash_at(&Address(Felt252::from(address)))
                .map_err(|e| PyRuntimeError::new_err(e.to_string()))?,
        ))
    }

    fn get_nonce_at(&mut self, address: BigUint) -> PyResult<BigUint> {
        Ok(self
            .state
            .get_nonce_at(&Address(Felt252::from(address)))
            .map_err(|e| PyRuntimeError::new_err(e.to_string()))?
            .to_biguint())
    }

    fn get_storage_at(&mut self, address: BigUint, key: BigUint) -> PyResult<BigUint> {
        Ok(self
            .state
            .get_storage_at(&(
                Address(Felt252::from(address)),
                felt_to_hash(&Felt252::from(key)),
            ))
            .map_err(|e| PyRuntimeError::new_err(e.to_string()))?
            .to_biguint())
    }

    fn set_contract_class(&mut self, _address: BigUint, _contract_class: &PyContractClass) {
        // self.state.set_contract_class(class_hash, contract_class)
        todo!()
    }

    fn set_storage_at(&mut self, address: BigUint, key: BigUint, value: BigUint) {
        self.state.set_storage_at(
            &(
                Address(Felt252::from(address)),
                felt_to_hash(&Felt252::from(key)),
            ),
            Felt252::from(value),
        );
    }
}
