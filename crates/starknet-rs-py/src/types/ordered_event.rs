use cairo_felt::Felt252;
use num_bigint::BigUint;
use pyo3::prelude::*;
use starknet_rs::business_logic::execution::objects::OrderedEvent;

#[pyclass]
#[pyo3(name = "OrderedEvent")]
#[derive(Debug)]
pub struct PyOrderedEvent {
    inner: OrderedEvent,
}

#[pymethods]
impl PyOrderedEvent {
    #[getter]
    fn order(&self) -> u64 {
        self.inner.order
    }

    #[getter]
    fn keys(&self) -> Vec<BigUint> {
        self.inner.keys.iter().map(Felt252::to_biguint).collect()
    }

    #[getter]
    fn data(&self) -> Vec<BigUint> {
        self.inner.data.iter().map(Felt252::to_biguint).collect()
    }
}

impl From<OrderedEvent> for PyOrderedEvent {
    fn from(inner: OrderedEvent) -> Self {
        Self { inner }
    }
}
