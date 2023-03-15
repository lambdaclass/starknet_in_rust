use num_bigint::BigUint;
use pyo3::prelude::*;
use starknet_rs::services::api::contract_class::ContractEntryPoint;

#[pyclass]
#[pyo3(name = "ContractEntryPoint")]
#[derive(Debug)]
pub struct PyContractEntryPoint {
    inner: ContractEntryPoint,
}

#[pymethods]
impl PyContractEntryPoint {
    pub fn selector(&self) -> BigUint {
        self.inner.selector().to_biguint()
    }

    pub fn function_idx(&self) -> i32 {
        todo!()
    }
}

impl From<ContractEntryPoint> for PyContractEntryPoint {
    fn from(inner: ContractEntryPoint) -> Self {
        Self { inner }
    }
}
