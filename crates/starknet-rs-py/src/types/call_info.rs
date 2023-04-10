use super::{
    execution_resources::PyExecutionResources, ordered_event::PyOrderedEvent,
    ordered_l2_to_l1_message::PyOrderedL2ToL1Message,
};
use cairo_felt::Felt252;
use num_bigint::BigUint;
use pyo3::prelude::*;
use starknet_rs::{
    business_logic::execution::objects::{CallInfo, CallType},
    services::api::contract_class::EntryPointType,
};

#[pyclass]
#[pyo3(name = "CallInfo")]
#[derive(Debug)]
pub struct PyCallInfo {
    inner: CallInfo,
}

#[pymethods]
impl PyCallInfo {
    #[getter]
    fn caller_address(&self) -> BigUint {
        self.inner.caller_address.0.to_biguint()
    }

    #[getter]
    fn call_type(&self) -> Option<u64> {
        Some(match self.inner.call_type.clone()? {
            CallType::Call => 0,
            CallType::Delegate => 1,
        })
    }

    #[getter]
    fn contract_address(&self) -> BigUint {
        self.inner.contract_address.0.to_biguint()
    }

    #[getter]
    fn class_hash(&self) -> Option<BigUint> {
        Some(Felt252::from_bytes_be(&self.inner.class_hash?).to_biguint())
    }

    #[getter]
    fn entry_point_selector(&self) -> Option<BigUint> {
        Some(self.inner.entry_point_selector.clone()?.to_biguint())
    }

    #[getter]
    fn entry_point_type(&self) -> Option<u64> {
        Some(match self.inner.entry_point_type? {
            EntryPointType::External => 0,
            EntryPointType::L1Handler => 1,
            EntryPointType::Constructor => 2,
        })
    }

    #[getter]
    fn calldata(&self) -> Vec<BigUint> {
        self.inner
            .calldata
            .iter()
            .map(Felt252::to_biguint)
            .collect()
    }

    #[getter]
    fn retdata(&self) -> Vec<BigUint> {
        self.inner.retdata.iter().map(Felt252::to_biguint).collect()
    }

    #[getter]
    fn execution_resources(&self) -> PyExecutionResources {
        self.inner.execution_resources.clone().into()
    }

    #[getter]
    fn events(&self) -> Vec<PyOrderedEvent> {
        self.inner.events.iter().cloned().map(Into::into).collect()
    }

    #[getter]
    fn l2_to_l1_messages(&self) -> Vec<PyOrderedL2ToL1Message> {
        self.inner
            .l2_to_l1_messages
            .iter()
            .cloned()
            .map(Into::into)
            .collect()
    }

    #[getter]
    fn storage_read_values(&self) -> Vec<BigUint> {
        self.inner
            .storage_read_values
            .iter()
            .map(Felt252::to_biguint)
            .collect()
    }

    #[getter]
    fn accessed_storage_keys(&self) -> Vec<BigUint> {
        self.inner
            .accessed_storage_keys
            .iter()
            .map(|x| Felt252::from_bytes_be(x).to_biguint())
            .collect()
    }

    #[getter]
    fn internal_calls(&self) -> Vec<PyCallInfo> {
        self.inner
            .internal_calls
            .iter()
            .cloned()
            .map(|inner| Self { inner })
            .collect()
    }
}

impl From<CallInfo> for PyCallInfo {
    fn from(inner: CallInfo) -> Self {
        Self { inner }
    }
}
