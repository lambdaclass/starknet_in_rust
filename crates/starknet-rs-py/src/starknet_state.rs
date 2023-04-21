use crate::cached_state::PyCachedState;
use crate::types::block_info::PyBlockInfo;
use crate::types::{
    call_info::PyCallInfo, contract_class::PyContractClass,
    general_config::PyStarknetGeneralConfig, transaction::PyTransaction,
    transaction_execution_info::PyTransactionExecutionInfo,
};
use cairo_vm::felt::Felt252;
use num_bigint::BigUint;
use pyo3::{exceptions::PyRuntimeError, prelude::*};
use starknet_rs::business_logic::state::state_api::{State, StateReader};
use starknet_rs::testing::starknet_state::StarknetState as InnerStarknetState;
use starknet_rs::utils::{Address, ClassHash};

#[pyclass(name = "StarknetState")]
pub struct PyStarknetState {
    inner: InnerStarknetState,
}

#[pymethods]
impl PyStarknetState {
    #[new]
    #[allow(unused_variables)]
    fn new(state: PyCachedState, general_config: PyStarknetGeneralConfig) -> Self {
        // TODO: this should use received state
        Self::empty(Some(general_config))
    }

    #[staticmethod]
    pub fn empty(config: Option<PyStarknetGeneralConfig>) -> Self {
        let config = config.map(|c| c.inner);
        PyStarknetState {
            inner: InnerStarknetState::new(config),
        }
    }

    pub fn declare(
        &mut self,
        contract_class: &PyContractClass,
    ) -> PyResult<([u8; 32], PyTransactionExecutionInfo)> {
        let (hash, exec_info) = self
            .inner
            .declare(contract_class.inner.clone())
            .map_err(|e| PyRuntimeError::new_err(e.to_string()))?;

        Ok((hash, PyTransactionExecutionInfo::from(exec_info)))
    }

    pub fn invoke_raw(
        &mut self,
        contract_address: BigUint,
        selector: BigUint,
        calldata: Vec<BigUint>,
        max_fee: u64,
        signature: Option<Vec<BigUint>>,
        nonce: Option<BigUint>,
    ) -> PyResult<PyTransactionExecutionInfo> {
        let address = Address(contract_address.into());
        let selector = selector.into();

        let calldata = calldata
            .into_iter()
            .map(Felt252::from)
            .collect::<Vec<Felt252>>();
        let signature = signature.map(|signs| {
            signs
                .into_iter()
                .map(Felt252::from)
                .collect::<Vec<Felt252>>()
        });

        let nonce = nonce.map(Felt252::from);

        let exec_info = self
            .inner
            .invoke_raw(address, selector, calldata, max_fee, signature, nonce)
            .map_err(|e| PyRuntimeError::new_err(e.to_string()))?;

        Ok(PyTransactionExecutionInfo::from(exec_info))
    }

    pub fn execute_entry_point_raw(
        &mut self,
        contract_address: BigUint,
        entry_point_selector: BigUint,
        calldata: Vec<BigUint>,
        caller_address: BigUint,
    ) -> PyResult<PyCallInfo> {
        let calldata = calldata
            .into_iter()
            .map(Felt252::from)
            .collect::<Vec<Felt252>>();
        let entry_point_selector = Felt252::from(entry_point_selector);

        let call_info = self
            .inner
            .execute_entry_point_raw(
                Address(Felt252::from(contract_address)),
                entry_point_selector,
                calldata,
                Address(Felt252::from(caller_address)),
            )
            .map_err(|e| PyRuntimeError::new_err(e.to_string()))?;

        Ok(PyCallInfo::from(call_info))
    }

    pub fn deploy(
        &mut self,
        contract_class: &PyContractClass,
        constructor_calldata: Vec<BigUint>,
        contract_address_salt: BigUint,
    ) -> PyResult<(BigUint, PyTransactionExecutionInfo)> {
        let contract_class = contract_class.inner.clone();
        let constructor_calldata = constructor_calldata
            .into_iter()
            .map(Felt252::from)
            .collect::<Vec<Felt252>>();
        let contract_address_salt = Address(Felt252::from(contract_address_salt));

        let (address, exec_info) = self
            .inner
            .deploy(contract_class, constructor_calldata, contract_address_salt)
            .map_err(|e| PyRuntimeError::new_err(e.to_string()))?;
        Ok((
            address.0.to_biguint(),
            PyTransactionExecutionInfo::from(exec_info),
        ))
    }

    pub fn execute_tx(&mut self, tx: &mut PyTransaction) -> PyResult<PyTransactionExecutionInfo> {
        let tx_info = self
            .inner
            .execute_tx(&mut tx.inner)
            .map_err(|e| PyRuntimeError::new_err(e.to_string()))?;
        Ok(PyTransactionExecutionInfo::from(tx_info))
    }

    pub fn consume_message_hash(&mut self, message_hash: Vec<u8>) -> PyResult<()> {
        self.inner
            .consume_message_hash(message_hash)
            .map_err(|e| PyRuntimeError::new_err(e.to_string()))?;
        Ok(())
    }

    fn set_contract_class(
        &mut self,
        hash: ClassHash,
        contract_class: &PyContractClass,
    ) -> PyResult<()> {
        self.inner
            .state
            .set_contract_class(&hash, &contract_class.inner.clone())
            .map_err(|e| PyRuntimeError::new_err(e.to_string()))?;
        Ok(())
    }

    fn deploy_contract(&mut self, address: BigUint, hash: ClassHash) -> PyResult<()> {
        let address = Address(Felt252::from(address));
        self.inner
            .state
            .deploy_contract(address, hash)
            .map_err(|e| PyRuntimeError::new_err(e.to_string()))?;
        Ok(())
    }

    pub fn set_storage_at(&mut self, address: BigUint, key: BigUint, value: BigUint) {
        let address = Address(Felt252::from(address));
        let key = (Felt252::from(key)).to_be_bytes();
        let value = Felt252::from(value);
        self.inner.state.set_storage_at(&(address, key), value);
    }

    #[getter]
    pub fn general_config(&self) -> PyStarknetGeneralConfig {
        self.inner.general_config.clone().into()
    }

    pub fn get_class_hash_at(&mut self, address: BigUint) -> PyResult<ClassHash> {
        self.inner
            .state
            .get_class_hash_at(&Address(Felt252::from(address)))
            .map_err(|e| PyRuntimeError::new_err(e.to_string()))
    }

    pub fn clone(&self) -> Self {
        let inner = self.inner.clone();
        Self { inner }
    }

    #[getter("block_info")]
    pub fn get_block_info(&self) -> PyBlockInfo {
        self.inner.general_config.block_info().clone().into()
    }

    #[setter("block_info")]
    pub fn set_block_info(&mut self, block_info: PyBlockInfo) {
        *self.inner.general_config.block_info_mut() = block_info.into();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pyo3::{types::IntoPyDict, PyTypeInfo, Python};

    #[test]
    fn starknet_state_constructor_test() {
        Python::with_gil(|py| {
            let general_config_cls = <PyStarknetGeneralConfig as PyTypeInfo>::type_object(py);
            let state_cls = <PyStarknetState as PyTypeInfo>::type_object(py);

            let locals = [
                ("StarknetGeneralConfig", general_config_cls),
                ("StarknetState", state_cls),
            ]
            .into_py_dict(py);

            let code = r#"
StarknetState.empty()
"#;

            let res = py.run(code, None, Some(locals));
            assert!(res.is_ok(), "{res:?}");
        })
    }
}
