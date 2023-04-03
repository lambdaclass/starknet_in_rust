use crate::types::block_info::PyBlockInfo;
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

#[pyclass(name = "CachedState")]
#[derive(Debug, Clone, Default)]
pub struct PyCachedState {
    state: InnerCachedState<InMemoryStateReader>,
}

#[pymethods]
impl PyCachedState {
    #[new]
    #[allow(unused_variables)]
    fn new(block_info: PyBlockInfo, state_reader: &PyAny, contract_class_cache: &PyAny) -> Self {
        // TODO: this should wrap state_reader with something that implements StateReader
        //  contract_class_cache and block_info can be safely ignored for the devnet
        Default::default()
    }

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

impl<'a> From<&'a mut PyCachedState> for &'a mut InnerCachedState<InMemoryStateReader> {
    fn from(state: &'a mut PyCachedState) -> Self {
        &mut state.state
    }
}
