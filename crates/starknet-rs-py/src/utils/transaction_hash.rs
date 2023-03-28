use cairo_felt::Felt252;
use num_bigint::BigUint;
use pyo3::{exceptions::PyValueError, prelude::*};
use starknet_rs::{
    core::transaction_hash::starknet_transaction_hash::{
        calculate_declare_transaction_hash, calculate_deploy_transaction_hash,
        calculate_transaction_hash_common, TransactionHashPrefix,
    },
    utils::Address,
};

use crate::types::contract_class::PyContractClass;

#[pyclass]
#[pyo3(name = "TransactionHashPrefix")]
#[derive(Debug)]
pub enum PyTransactionHashPrefix {
    #[pyo3(name = "DECLARE")]
    Declare,
    #[pyo3(name = "DEPLOY")]
    Deploy,
    #[pyo3(name = "DEPLOY_ACCOUNT")]
    DeployAccount,
    #[pyo3(name = "INVOKE")]
    Invoke,
    #[pyo3(name = "L1_HANDLER")]
    L1Handler,
}

impl From<TransactionHashPrefix> for PyTransactionHashPrefix {
    fn from(prefix: TransactionHashPrefix) -> Self {
        match prefix {
            TransactionHashPrefix::Declare => Self::Declare,
            TransactionHashPrefix::Deploy => Self::Deploy,
            TransactionHashPrefix::DeployAccount => Self::DeployAccount,
            TransactionHashPrefix::Invoke => Self::Invoke,
            TransactionHashPrefix::L1Handler => Self::L1Handler,
        }
    }
}

impl From<&PyTransactionHashPrefix> for TransactionHashPrefix {
    fn from(prefix: &PyTransactionHashPrefix) -> Self {
        match prefix {
            PyTransactionHashPrefix::Declare => Self::Declare,
            PyTransactionHashPrefix::Deploy => Self::Deploy,
            PyTransactionHashPrefix::DeployAccount => Self::DeployAccount,
            PyTransactionHashPrefix::Invoke => Self::Invoke,
            PyTransactionHashPrefix::L1Handler => Self::L1Handler,
        }
    }
}

#[pyfunction]
#[pyo3(name = "calculate_deploy_transaction_hash")]
pub(crate) fn py_calculate_deploy_transaction_hash(
    version: u64,
    contract_address: BigUint,
    constructor_calldata: Vec<BigUint>,
    chain_id: BigUint,
) -> PyResult<BigUint> {
    let contract_address = Address(Felt252::from(contract_address));
    let constructor_calldata: Vec<_> = constructor_calldata.into_iter().map(Into::into).collect();
    let chain_id = Felt252::from(chain_id);
    match calculate_deploy_transaction_hash(
        version,
        &contract_address,
        &constructor_calldata,
        chain_id,
    ) {
        Ok(res) => Ok(res.to_biguint()),
        Err(err) => Err(PyValueError::new_err(err.to_string())),
    }
}

#[pyfunction]
#[pyo3(name = "calculate_declare_transaction_hash")]
pub(crate) fn py_calculate_declare_transaction_hash(
    contract_class: &PyContractClass,
    chain_id: BigUint,
    sender_address: BigUint,
    max_fee: u64,
    version: u64,
    nonce: BigUint,
) -> PyResult<BigUint> {
    let chain_id = Felt252::from(chain_id);
    let sender_address = Address(Felt252::from(sender_address));
    let nonce = Felt252::from(nonce);
    match calculate_declare_transaction_hash(
        contract_class.into(),
        chain_id,
        &sender_address,
        max_fee,
        version,
        nonce,
    ) {
        Ok(res) => Ok(res.to_biguint()),
        Err(err) => Err(PyValueError::new_err(err.to_string())),
    }
}

#[pyfunction]
#[pyo3(name = "calculate_transaction_hash_common")]
pub(crate) fn py_calculate_transaction_hash_common(
    tx_hash_prefix: &PyTransactionHashPrefix,
    version: u64,
    contract_address: BigUint,
    entry_point_selector: BigUint,
    calldata: Vec<BigUint>,
    max_fee: u64,
    chain_id: BigUint,
    additional_data: Vec<BigUint>,
) -> PyResult<BigUint> {
    let tx_hash_prefix = tx_hash_prefix.into();
    let contract_address = Address(Felt252::from(contract_address));
    let entry_point_selector = Felt252::from(entry_point_selector);
    let chain_id = Felt252::from(chain_id);
    let calldata: Vec<_> = calldata.into_iter().map(Felt252::from).collect();
    let additional_data: Vec<_> = additional_data.into_iter().map(Felt252::from).collect();

    match calculate_transaction_hash_common(
        tx_hash_prefix,
        version,
        &contract_address,
        entry_point_selector,
        &calldata,
        max_fee,
        chain_id,
        &additional_data,
    ) {
        Ok(res) => Ok(res.to_biguint()),
        Err(err) => Err(PyValueError::new_err(err.to_string())),
    }
}
