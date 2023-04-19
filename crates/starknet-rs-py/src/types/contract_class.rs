use super::contract_entry_point::PyContractEntryPoint;
use cairo_vm::types::errors::program_errors::ProgramError;
use pyo3::prelude::*;
use pyo3::{
    exceptions::PyValueError,
    types::{IntoPyDict, PyDict, PyString, PyType},
};
use starknet_rs::services::api::contract_class::{ContractClass, EntryPointType};
use std::collections::HashMap;

type PyEntryPointType = i32;

#[pyclass(name = "ContractClass")]
#[derive(Debug, Clone)]
pub struct PyContractClass {
    pub(crate) inner: ContractClass,
    abi: Option<Py<PyAny>>,
}

#[pymethods]
impl PyContractClass {
    #[new]
    pub fn new(path: &PyString) -> Self {
        let path = path.to_str().unwrap();
        PyContractClass {
            inner: ContractClass::try_from(path).unwrap(),
            abi: None,
        }
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
    pub fn abi(&self, _py: Python) -> Option<&Py<PyAny>> {
        // TODO: this should be retrieved from self.inner
        self.abi.as_ref()
    }

    #[classmethod]
    fn load(cls: &PyType, data: &PyDict, py: Python) -> PyResult<Self> {
        // TODO: parse PyDict directly to avoid having to serialize
        let json = PyModule::import(py, "json")?;

        let abi = data.get_item("abi").map(Py::from);

        let data: &PyAny = data.into();
        let dict = [("data", data), ("json", json.into())].into_py_dict(py);
        let s: &str = py.eval("json.dumps(data)", None, Some(dict))?.extract()?;

        Ok(Self {
            abi,
            ..Self::loads(cls, s)?
        })
    }

    #[classmethod]
    fn loads(_cls: &PyType, s: &str) -> PyResult<Self> {
        Self::try_from(s).map_err(|err| PyValueError::new_err(err.to_string()))
    }
}

impl<'a> From<&'a PyContractClass> for &'a ContractClass {
    fn from(class: &'a PyContractClass) -> Self {
        &class.inner
    }
}

impl TryFrom<&str> for PyContractClass {
    type Error = ProgramError;

    fn try_from(s: &str) -> Result<Self, Self::Error> {
        Ok(Self {
            inner: ContractClass::try_from(s)?,
            abi: None,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pyo3::PyTypeInfo;
    use std::path::PathBuf;

    #[test]
    fn test_create_py_contract_class() {
        Python::with_gil(|py| {
            let py_contract_cls = <PyContractClass as PyTypeInfo>::type_object(py);

            let locals = [("ContractClass", py_contract_cls)].into_py_dict(py);

            let code = r#"
file = open('../../starknet_programs/fibonacci.json')
ContractClass(file.read())
file.close()
"#;

            let res = py.run(code, None, Some(locals));
            assert!(res.is_ok(), "{res:?}");
        })
    }

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
