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
    #[new]
    pub fn new(path: &str) -> Self {
        PyContractClass {
            inner: ContractClass::try_from(path).unwrap(),
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
    pub fn abi(&self) -> PyResult<String> {
        serde_json::to_string(&self.inner.abi()).map_err(|e| PyRuntimeError::new_err(e.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pyo3::{types::IntoPyDict, PyTypeInfo, Python};

    #[test]
    fn test_create_py_contract_class() {
        Python::with_gil(|py| {
            let py_contract_cls = <PyContractClass as PyTypeInfo>::type_object(py);

            let locals = [("ContractClass", py_contract_cls)].into_py_dict(py);

            let code = r#"
contract = open("../../../../starknet_programs/fibonacci.json")
ContractClass(contract)
"#;

            let res = py.run(code, None, Some(locals));
            assert!(res.is_ok(), "{res:?}");
        })
    }
}
