use std::collections::HashMap;

use crate::types::contract_class::PyContractClass;
use cairo_felt::Felt;
use num_bigint::BigUint;
use pyo3::{exceptions::PyRuntimeError, prelude::*};
use starknet_rs::{
    business_logic::{
        fact_state::in_memory_state_reader::InMemoryStateReader,
        state::{
            cached_state::CachedState as InnerCachedState,
            state_api::{State, StateReader},
        },
    },
    utils::{felt_to_hash, Address},
};

#[pyclass]
#[pyo3(name = "CachedState")]
#[derive(Debug)]
pub struct PyCachedState {
    state: InnerCachedState<InMemoryStateReader>,
}

#[pymethods]
impl PyCachedState {
    #[new]
    pub fn new() -> Self {
        let cached_state =
            InnerCachedState::new(InMemoryStateReader::default(), Some(HashMap::new()));
        PyCachedState {
            state: cached_state,
        }
    }

    fn get_class_hash_at(&mut self, address: BigUint) -> PyResult<BigUint> {
        Ok(BigUint::from_bytes_be(
            self.state
                .get_class_hash_at(&Address(Felt::from(address)))
                .map_err(|e| PyRuntimeError::new_err(e.to_string()))?,
        ))
    }

    fn get_nonce_at(&mut self, address: BigUint) -> PyResult<BigUint> {
        Ok(self
            .state
            .get_nonce_at(&Address(Felt::from(address)))
            .map_err(|e| PyRuntimeError::new_err(e.to_string()))?
            .to_biguint())
    }

    fn get_storage_at(&mut self, address: BigUint, key: BigUint) -> PyResult<BigUint> {
        Ok(self
            .state
            .get_storage_at(&(Address(Felt::from(address)), felt_to_hash(&Felt::from(key))))
            .map_err(|e| PyRuntimeError::new_err(e.to_string()))?
            .to_biguint())
    }

    fn set_contract_class(
        &mut self,
        address: BigUint,
        contract_class: &PyContractClass,
    ) -> PyResult<()> {
        let address = felt_to_hash(&Felt::from(address));
        let contract_class = contract_class.inner.clone();
        self.state
            .set_contract_class(&address, &contract_class)
            .map_err(|e| PyRuntimeError::new_err(e.to_string()))?;
        Ok(())
    }

    fn set_storage_at(&mut self, address: BigUint, key: BigUint, value: BigUint) {
        self.state.set_storage_at(
            &(Address(Felt::from(address)), felt_to_hash(&Felt::from(key))),
            Felt::from(value),
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pyo3::{types::IntoPyDict, PyTypeInfo, Python};

    #[test]
    fn test_set_contract_class() {
        Python::with_gil(|py| {
            let py_contract_cls = <PyContractClass as PyTypeInfo>::type_object(py);
            let py_state_cls = <PyCachedState as PyTypeInfo>::type_object(py);

            let locals = [
                ("ContractClass", py_contract_cls),
                ("CachedState", py_state_cls),
            ]
            .into_py_dict(py);

            let code = r#"
file = open('../../starknet_programs/fibonacci.json')
c = ContractClass(file.read())
file.close()
state = CachedState()
state.set_contract_class(1, c)
"#;

            let res = py.run(code, None, Some(locals));
            assert!(res.is_ok(), "{res:?}");
        })
    }
}
