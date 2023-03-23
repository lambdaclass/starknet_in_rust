use super::contract_entry_point::PyContractEntryPoint;
use pyo3::{exceptions::PyRuntimeError, prelude::*};
use starknet_rs::services::api::contract_class::{ContractClass, EntryPointType};
use std::collections::HashMap;

type PyEntryPointType = i32;

#[pyclass]
#[pyo3(name = "ContractClass")]
#[derive(Debug)]
pub struct PyContractClass {
    pub(crate) inner: ContractClass,
}

#[pymethods]
impl PyContractClass {
    #[getter]
    pub fn entry_points_by_type(&self) -> HashMap<PyEntryPointType, Vec<PyContractEntryPoint>> {
        self.inner
            .entry_points_by_type()
            .iter()
            .map(|(k, v)| {
                (
                    match k {
                        EntryPointType::External => 0,
                        EntryPointType::L1Handler => 1,
                        EntryPointType::Constructor => 2,
                    },
                    v.iter().cloned().map(PyContractEntryPoint::from).collect(),
                )
            })
            .collect()
    }

    #[getter]
    pub fn abi(&self) -> PyResult<String> {
        serde_json::to_string(&self.inner.abi()).map_err(|e| PyRuntimeError::new_err(e.to_string()))
    }
}
