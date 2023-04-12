use super::call_info::PyCallInfo;
use pyo3::prelude::*;
use starknet_rs::business_logic::execution::objects::TransactionExecutionInfo;
use std::collections::HashMap;

#[pyclass(name = "TransactionExecutionInfo")]
#[derive(Debug)]
pub struct PyTransactionExecutionInfo {
    inner: TransactionExecutionInfo,
}

#[pymethods]
impl PyTransactionExecutionInfo {
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
