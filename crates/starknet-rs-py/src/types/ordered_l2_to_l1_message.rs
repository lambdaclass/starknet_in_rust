use cairo_felt::Felt252;
use num_bigint::BigUint;
use pyo3::prelude::*;
use starknet_rs::business_logic::execution::objects::OrderedL2ToL1Message;

#[pyclass]
#[pyo3(name = "OrderedEvent")]
#[derive(Debug)]
pub struct PyOrderedL2ToL1Message {
    inner: OrderedL2ToL1Message,
}

#[pymethods]
impl PyOrderedL2ToL1Message {
    #[getter]
    fn order(&self) -> usize {
        self.inner.order
    }

    #[getter]
    fn to_address(&self) -> BigUint {
        self.inner.to_address.0.to_biguint()
    }

    #[getter]
    fn payload(&self) -> Vec<BigUint> {
        self.inner.payload.iter().map(Felt252::to_biguint).collect()
    }
}

impl From<OrderedL2ToL1Message> for PyOrderedL2ToL1Message {
    fn from(inner: OrderedL2ToL1Message) -> Self {
        Self { inner }
    }
}
