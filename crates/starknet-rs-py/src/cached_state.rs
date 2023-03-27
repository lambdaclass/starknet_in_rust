use cairo_felt::Felt;
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
                .get_class_hash_at(&Address(Felt::from(address)))
                .map_err(|e| PyRuntimeError::new_err(e.to_string()))?,
        ))
    }

    fn get_nonce_at(&mut self, address: BigUint) -> PyResult<BigUint> {
        Ok(self
            .state
            .get_nonce_at(&Address(Felt::from(address)))
            .map_err(|e| PyRuntimeError::new_err(e.to_string()))?
            .to_biguint())
    }

    fn get_storage_at(&mut self, address: BigUint, key: BigUint) -> PyResult<BigUint> {
        Ok(self
            .state
            .get_storage_at(&(Address(Felt::from(address)), felt_to_hash(&Felt::from(key))))
            .map_err(|e| PyRuntimeError::new_err(e.to_string()))?
            .to_biguint())
    }

    fn set_storage_at(&mut self, address: BigUint, key: BigUint, value: BigUint) {
        self.state.set_storage_at(
            &(Address(Felt::from(address)), felt_to_hash(&Felt::from(key))),
            Felt::from(value),
        );
    }
}
