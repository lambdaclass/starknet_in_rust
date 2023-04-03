use super::contract_entry_point::PyContractEntryPoint;
use pyo3::{
    exceptions::PyRuntimeError,
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
        serde_json::to_string(&self.inner.abi()).map_err(|e| PyRuntimeError::new_err(e.to_string()))
    }

    #[classmethod]
    fn load(cls: &PyType, data: &PyDict, py: Python) -> PyResult<Self> {
        // TODO:
        //   1. fix ContractClass deserialization
        //   2. parse PyDict directly to avoid having to serialize

        let json = PyModule::import(py, "json")?;
        let data: &PyAny = data.into();
        let dict = [("data", data), ("json", json.into())].into_py_dict(py);
        let s: &str = py.eval("json.dumps(data)", None, Some(dict))?.extract()?;
        Self::loads(cls, s)
    }

    #[classmethod]
    fn loads(_cls: &PyType, _s: &str) -> PyResult<Self> {
        // match serde_json::from_str(&s) {
        //     Ok(inner) => Ok(Self { inner }),
        //     Err(err) => Err(PyValueError::new_err(err.to_string())),
        // }
        let inner = ContractClass::new(Default::default(), Default::default(), None).unwrap();
        Ok(PyContractClass { inner })
    }
}

impl<'a> From<&'a PyContractClass> for &'a ContractClass {
    fn from(class: &'a PyContractClass) -> Self {
        &class.inner
    }
}

#[cfg(test)]
mod tests {
    use pyo3::PyTypeInfo;

    use super::*;

    #[test]
    fn load_contract_smoke_test() {
        Python::with_gil(|py| {
            let cls = PyContractClass::type_object(py);
            let dict = include_str!("../../../../tests/test_data/example_class.json");
            let data = py
                .eval(dict, None, None)
                .and_then(PyAny::extract)
                .expect("should eval to PyDict");

            let contract_class = PyContractClass::load(cls, data, py);

            assert!(contract_class.is_ok());
        });
    }
}
