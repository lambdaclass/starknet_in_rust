use super::contract_entry_point::PyContractEntryPoint;
use pyo3::prelude::*;
use starknet_rs::services::api::contract_class::{ContractClass, EntryPointType};
use std::collections::HashMap;

type PyEntryPointType = i32;

#[pyclass]
pub struct PyContractClass {
    inner: ContractClass,
}

#[pymethods]
impl PyContractClass {
    #[getter]
    pub fn contract_class_version(&self) -> &str {
        todo!()
    }

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
    pub fn abi(&self) -> &str {
        todo!()
    }
}
