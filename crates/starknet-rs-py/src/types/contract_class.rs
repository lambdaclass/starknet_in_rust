use super::contract_entry_point::PyContractEntryPoint;
use pyo3::{
    exceptions::{PyRuntimeError, PyValueError},
    prelude::*,
    types::{IntoPyDict, PyDict, PyType},
};
use starknet_rs::services::api::contract_class::{ContractClass, EntryPointType};
use std::collections::HashMap;

type PyEntryPointType = i32;

#[pyclass(name = "ContractClass")]
#[derive(Debug, Clone)]
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
        // TODO: this should return Option<PyAbiType>
        serde_json::to_string(&self.inner.abi()).map_err(|e| PyRuntimeError::new_err(e.to_string()))
    }

    #[classmethod]
    fn load(cls: &PyType, data: &PyDict, py: Python) -> PyResult<Self> {
        // TODO: parse PyDict directly to avoid having to serialize
        let json = PyModule::import(py, "json")?;
        let data: &PyAny = data.into();
        let dict = [("data", data), ("json", json.into())].into_py_dict(py);
        let s: &str = py.eval("json.dumps(data)", None, Some(dict))?.extract()?;
        Self::loads(cls, s)
    }

    #[classmethod]
    fn loads(_cls: &PyType, s: &str) -> PyResult<Self> {
        match ContractClass::try_from(s) {
            Ok(inner) => Ok(Self { inner }),
            Err(err) => Err(PyValueError::new_err(err.to_string())),
        }
    }
}

impl<'a> From<&'a PyContractClass> for &'a ContractClass {
    fn from(class: &'a PyContractClass) -> Self {
        &class.inner
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pyo3::PyTypeInfo;
    use std::path::PathBuf;

    #[test]
    fn load_contract_smoke_test() {
        Python::with_gil(|py| {
            let dict = std::fs::read_to_string(PathBuf::from(
                "../../starknet_programs/account_without_validation.json",
            ))
            .expect("should be able to read file");

            // All our contracts have 'null' flow_tracking_data, and that causes Python to blow up
            let locals = [("null", PyDict::new(py))].into_py_dict(py);

            let data = py
                .eval(dict.as_str(), None, Some(locals))
                .and_then(PyAny::extract)
                .expect("should eval to PyDict");

            let cls = PyContractClass::type_object(py);
            let contract_class = PyContractClass::load(cls, data, py);

            assert!(contract_class.is_ok());
        });
    }
}
