use cairo_felt::Felt252;
use num_bigint::BigUint;
use pyo3::prelude::*;
use starknet_rs::{services::api::messages::StarknetMessageToL1, utils::Address};

#[pyclass]
pub struct PyStarknetMessageToL1 {
    inner: StarknetMessageToL1,
}

#[pymethods]
impl PyStarknetMessageToL1 {
    #[new]
    fn new(from_address: BigUint, to_address: BigUint, payload: Vec<BigUint>) -> Self {
        let from_address = Address(Felt252::from(from_address));
        let to_address = Address(Felt252::from(to_address));
        let payload: Vec<_> = payload.into_iter().map(Felt252::from).collect();

        let inner = StarknetMessageToL1::new(from_address, to_address, payload);
        Self { inner }
    }

    fn encode(&self) -> Vec<BigUint> {
        self.inner
            .encode()
            .iter()
            .map(Felt252::to_biguint)
            .collect()
    }

    fn get_hash(&self) -> Vec<u8> {
        self.inner.get_hash()
    }
}
