use crate::types::{
    call_info::PyCallInfo, contract_class::PyContractClass,
    general_config::PyStarknetGeneralConfig, transaction::PyTransaction,
    transaction_execution_info::PyTransactionExecutionInfo,
};
use cairo_vm::felt::Felt252;
use num_bigint::BigUint;
use pyo3::{exceptions::PyRuntimeError, prelude::*};
use starknet_rs::business_logic::state::state_api::State;
use starknet_rs::testing::starknet_state::StarknetState as InnerStarknetState;
use starknet_rs::utils::{Address, ClassHash};

#[pyclass]
#[pyo3(name = "StarknetState")]
pub struct PyStarknetState {
    inner: InnerStarknetState,
}

#[pymethods]
impl PyStarknetState {
    #[pyo3(name = "empty")]
    #[staticmethod]
    pub fn new(config: Option<PyStarknetGeneralConfig>) -> Self {
        let config = config.map(|c| c.inner);
        PyStarknetState {
            inner: InnerStarknetState::new(config),
        }
    }

    pub fn declare(
        &mut self,
        contract_class: &PyContractClass,
        hash_value: Option<[u8; 32]>,
    ) -> PyResult<([u8; 32], PyTransactionExecutionInfo)> {
        let hash_value = hash_value.map(|f| Felt252::from_bytes_be(&f));
        let (hash, exec_info) = self
            .inner
            .declare(contract_class.inner.clone(), hash_value)
            .map_err(|e| PyRuntimeError::new_err(e.to_string()))?;

        Ok((hash, PyTransactionExecutionInfo::from(exec_info)))
    }

    #[allow(clippy::too_many_arguments)]
    pub fn invoke_raw(
        &mut self,
        contract_address: BigUint,
        selector: BigUint,
        calldata: Vec<BigUint>,
        max_fee: u64,
        signature: Option<Vec<BigUint>>,
        nonce: Option<BigUint>,
        hash_value: Option<[u8; 32]>,
    ) -> PyResult<PyTransactionExecutionInfo> {
        let address = Address(contract_address.into());
        let selector = selector.into();
        let hash_value = hash_value.map(|f| Felt252::from_bytes_be(&f));

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
            .invoke_raw(
                address, selector, calldata, max_fee, signature, nonce, hash_value,
            )
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
        hash_value: Option<BigUint>,
    ) -> PyResult<(BigUint, PyTransactionExecutionInfo)> {
        let contract_class = contract_class.inner.clone();
        let hash_value = hash_value.map(|f| f.into());
        let constructor_calldata = constructor_calldata
            .into_iter()
            .map(Felt252::from)
            .collect::<Vec<Felt252>>();
        let contract_address_salt = Address(Felt252::from(contract_address_salt));

        let (address, exec_info) = self
            .inner
            .deploy(
                contract_class,
                constructor_calldata,
                contract_address_salt,
                hash_value,
            )
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
