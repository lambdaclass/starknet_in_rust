use num_bigint::BigUint;
use pyo3::prelude::*;
use starknet_rs::{business_logic::transaction::transactions::Transaction, utils::ClassHash};

#[pyclass]
#[pyo3(name = "TransactionExecutionInfo")]
pub struct PyTransaction {
    pub(crate) inner: Transaction,
}

#[pymethods]
impl PyTransaction {
    #[getter]
    fn contract_hash(&self) -> ClassHash {
        self.inner.contract_hash()
    }
    #[getter]
    fn contract_address(&self) -> BigUint {
        self.inner.contract_address().0.to_biguint()
    }
}

impl From<Transaction> for PyTransaction {
    fn from(value: Transaction) -> Self {
        Self { inner: value }
    }
}
