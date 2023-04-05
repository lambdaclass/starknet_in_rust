use super::{call_info::PyCallInfo, transaction::PyTransactionType};
use pyo3::prelude::*;
use starknet_rs::business_logic::execution::objects::TransactionExecutionInfo;
use std::collections::HashMap;

#[pyclass(name = "TransactionExecutionInfo")]
#[derive(Clone, Debug, Default, PartialEq)]
pub struct PyTransactionExecutionInfo {
    inner: TransactionExecutionInfo,
}

#[pymethods]
impl PyTransactionExecutionInfo {
    #[new]
    fn new(
        actual_fee: u64,
        actual_resources: HashMap<String, usize>,
        validate_info: Option<PyCallInfo>,
        call_info: Option<PyCallInfo>,
        fee_transfer_info: Option<PyCallInfo>,
        tx_type: Option<PyTransactionType>,
    ) -> Self {
        let inner = TransactionExecutionInfo::new(
            validate_info.map(Into::into),
            call_info.map(Into::into),
            fee_transfer_info.map(Into::into),
            actual_fee,
            actual_resources,
            tx_type.map(Into::into),
        );
        Self { inner }
    }

    #[getter]
    fn validate_info(&self) -> Option<PyCallInfo> {
        self.inner.validate_info.clone().map(Into::into)
    }

    #[getter]
    fn call_info(&self) -> Option<PyCallInfo> {
        self.inner.call_info.clone().map(Into::into)
    }

    #[getter]
    fn fee_transfer_info(&self) -> Option<PyCallInfo> {
        self.inner.fee_transfer_info.clone().map(Into::into)
    }

    #[getter]
    fn actual_fee(&self) -> u64 {
        self.inner.actual_fee
    }

    #[getter]
    fn actual_resources(&self) -> HashMap<String, usize> {
        self.inner.actual_resources.clone()
    }

    #[getter]
    fn transaction_type(&self) -> Option<u64> {
        Some(self.inner.tx_type?.into())
    }
}

impl From<TransactionExecutionInfo> for PyTransactionExecutionInfo {
    fn from(inner: TransactionExecutionInfo) -> Self {
        Self { inner }
    }
}
