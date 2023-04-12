use num_bigint::BigUint;
use pyo3::prelude::*;
use starknet_rs::{business_logic::transaction::transactions::Transaction, utils::ClassHash};

#[pyclass(name = "Transaction")]
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

#[pyclass(name = "TransactionType")]
#[derive(Debug, PartialEq, Copy, Clone, Eq, Hash)]
pub enum PyTransactionType {
    #[pyo3(name = "DECLARE")]
    Declare,
    #[pyo3(name = "DEPLOY")]
    Deploy,
    #[pyo3(name = "DEPLOY_ACCOUNT")]
    DeployAccount,
    #[pyo3(name = "INITIALIZE_BLOCK_INFO")]
    InitializeBlockInfo,
    #[pyo3(name = "INVOKE_FUNCTION")]
    InvokeFunction,
    #[pyo3(name = "L1_HANDLER")]
    L1Handler,
}

// TODO: remove impl when pyo3 adds Enum subclassing
// https://github.com/PyO3/pyo3/issues/2887
#[pymethods]
impl PyTransactionType {
    #[getter]
    fn name(&self) -> &str {
        match self {
            Self::Declare => "DECLARE",
            Self::Deploy => "DEPLOY",
            Self::DeployAccount => "DEPLOY_ACCOUNT",
            Self::InitializeBlockInfo => "INITIALIZE_BLOCK_INFO",
            Self::InvokeFunction => "INVOKE_FUNCTION",
            Self::L1Handler => "L1_HANDLER",
        }
    }
}
