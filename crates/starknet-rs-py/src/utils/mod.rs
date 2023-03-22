use crate::types::general_config::PyStarknetGeneralConfig;
use num_bigint::BigUint;
use pyo3::{exceptions::PyValueError, pyfunction, PyResult};
use starknet_rs::business_logic::transaction::fee::calculate_tx_fee;
use std::collections::HashMap;

#[pyfunction]
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
