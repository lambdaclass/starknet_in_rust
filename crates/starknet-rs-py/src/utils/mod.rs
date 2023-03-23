use crate::types::contract_class::PyContractClass;
use crate::types::general_config::PyStarknetGeneralConfig;
use num_bigint::BigUint;
use pyo3::{exceptions::PyValueError, pyfunction, PyResult};
use starknet_rs::{
    business_logic::transaction::fee::calculate_tx_fee,
    core::contract_address::starknet_contract_address::compute_class_hash,
};
use std::collections::HashMap;

#[pyfunction]
#[pyo3(name = "calculate_tx_fee")]
pub(crate) fn py_calculate_tx_fee(
    resources: HashMap<String, usize>,
    gas_price: u64,
    general_config: PyStarknetGeneralConfig,
) -> PyResult<BigUint> {
    match calculate_tx_fee(&resources, gas_price, &general_config.into()) {
        Ok(res) => Ok(BigUint::from(res)),
        Err(err) => Err(PyValueError::new_err(err.to_string())),
    }
}

#[pyfunction]
#[pyo3(name = "compute_class_hash")]
pub(crate) fn py_compute_class_hash(contract_class: &PyContractClass) -> PyResult<BigUint> {
    match compute_class_hash(contract_class.into()) {
        Ok(res) => Ok(res.to_biguint()),
        Err(err) => Err(PyValueError::new_err(err.to_string())),
    }
}
