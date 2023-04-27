use cairo_vm::felt::Felt252;
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
    utils::{Address, ClassHash},
};

use crate::types::contract_class::PyContractClass;

#[pyclass]
#[pyo3(name = "CachedState")]
#[derive(Debug, Default, Clone)]
pub struct PyCachedState {
    state: InnerCachedState<InMemoryStateReader>,
}

#[pymethods]
impl PyCachedState {
    #[new]
    #[allow(unused_variables)]
    // TODO: Add block_info, state_reader (PyAny) and contract_classes (PyAny) as parameteters
    fn new() -> Self {
        // TODO: this should wrap state_reader with something that implements StateReader
        //  contract_class_cache and block_info can be safely ignored for the devnet
        Default::default()
    }

    fn get_class_hash_at(&mut self, address: BigUint) -> PyResult<BigUint> {
        Ok(BigUint::from_bytes_be(
            &self
                .state
                .get_class_hash_at(&Address(Felt252::from(address)))
                .map_err(|e| PyRuntimeError::new_err(e.to_string()))?,
        ))
    }

    fn get_nonce_at(&mut self, address: BigUint) -> PyResult<BigUint> {
        Ok(self
            .state
            .get_nonce_at(&Address(Felt252::from(address)))
            .map_err(|e| PyRuntimeError::new_err(e.to_string()))?
            .to_biguint())
    }

    fn get_storage_at(&mut self, address: BigUint, key: BigUint) -> PyResult<BigUint> {
        Ok(self
            .state
            .get_storage_at(&(
                Address(Felt252::from(address)),
                Felt252::from(key).to_be_bytes(),
            ))
            .map_err(|e| PyRuntimeError::new_err(e.to_string()))?
            .to_biguint())
    }

    fn set_contract_class(
        &mut self,
        address: ClassHash,
        contract_class: &PyContractClass,
    ) -> PyResult<()> {
        let contract_class = contract_class.inner.clone();
        self.state
            .set_contract_class(&address, &contract_class)
            .map_err(|e| PyRuntimeError::new_err(e.to_string()))?;
        Ok(())
    }

    fn set_storage_at(&mut self, address: BigUint, key: BigUint, value: BigUint) {
        self.state.set_storage_at(
            &(
                Address(Felt252::from(address)),
                Felt252::from(key).to_be_bytes(),
            ),
            Felt252::from(value),
        );
    }
}

impl<'a> From<&'a mut PyCachedState> for &'a mut InnerCachedState<InMemoryStateReader> {
    fn from(state: &'a mut PyCachedState) -> Self {
        &mut state.state
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pyo3::{types::IntoPyDict, PyTypeInfo, Python};

    // TODO: once that we can create a CachedState without default, we have to change the final assert to "is_ok"
    #[test]
    fn test_set_contract_class() {
        Python::with_gil(|py| {
            let py_contract_cls = <PyContractClass as PyTypeInfo>::type_object(py);
            let py_state_cls = <PyCachedState as PyTypeInfo>::type_object(py);
            // let py_block_cls = <PyBlockInfo as PyTypeInfo>::type_object(py);

            let locals = [
                ("ContractClass", py_contract_cls),
                ("CachedState", py_state_cls),
                //("BlockInfo", py_block_cls),
            ]
            .into_py_dict(py);

            let code = r#"
file = open('../../starknet_programs/fibonacci.json')
c = ContractClass(file.read())
file.close()
state = CachedState()
class_hash = [1] * 32
state.set_contract_class(class_hash, c)
"#;

            let res = py.run(code, None, Some(locals));
            assert!(res.is_err(), "{res:?}");
        })
    }
}
