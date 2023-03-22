use cairo_felt::Felt;
use num_bigint::BigUint;
use pyo3::{exceptions::PyRuntimeError, prelude::*};
use starknet_rs::{
    testing::{starknet_state::StarknetState as InnerStarknetState, type_utils::ExecutionInfo},
    utils::Address,
};

use crate::types::{
    call_info::PyCallInfo, contract_class::PyContractClass, transaction::PyTransaction,
    transaction_execution_info::PyTransactionExecutionInfo,
};
#[pyclass]
#[pyo3(name = "StarknetState")]
pub struct PyStarknetState {
    inner: InnerStarknetState,
}

impl PyStarknetState {
    pub fn declare(
        &mut self,
        contract_class: PyContractClass,
    ) -> PyResult<([u8; 32], PyTransactionExecutionInfo)> {
        let (hash, exec_info) = self
            .inner
            .declare(contract_class.inner)
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
            .map(|v| Felt::from(v))
            .collect::<Vec<Felt>>();
        let signature = match signature {
            Some(signs) => Some(
                signs
                    .into_iter()
                    .map(|v| Felt::from(v))
                    .collect::<Vec<Felt>>(),
            ),
            None => None,
        };

        let nonce = match nonce {
            Some(n) => Some(Felt::from(n)),
            None => None,
        };

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
            .map(|v| Felt::from(v))
            .collect::<Vec<Felt>>();
        let entry_point_selector = Felt::from(entry_point_selector);

        let call_info = self
            .inner
            .execute_entry_point_raw(
                Address(Felt::from(contract_address)),
                entry_point_selector,
                calldata,
                Address(Felt::from(caller_address)),
            )
            .map_err(|e| PyRuntimeError::new_err(e.to_string()))?;

        Ok(PyCallInfo::from(call_info))
    }

    pub fn deploy(
        &mut self,
        contract_class: PyContractClass,
        constructor_calldata: Vec<BigUint>,
        contract_address_salt: BigUint,
    ) -> PyResult<(BigUint, PyTransactionExecutionInfo)> {
        let contract_class = contract_class.inner;
        let constructor_calldata = constructor_calldata
            .into_iter()
            .map(|v| Felt::from(v))
            .collect::<Vec<Felt>>();
        let contract_address_salt = Address(Felt::from(contract_address_salt));

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
    pub fn add_messages_and_events(&mut self, exec_info: &ExecutionInfo) -> PyResult<()> {
        self.inner
            .add_messages_and_events(exec_info)
            .map_err(|e| PyRuntimeError::new_err(e.to_string()))?;
        Ok(())
    }

    pub fn consume_message_hash(&mut self, message_hash: Vec<u8>) -> PyResult<()> {
        self.inner
            .consume_message_hash(message_hash)
            .map_err(|e| PyRuntimeError::new_err(e.to_string()))?;
        Ok(())
    }
}
