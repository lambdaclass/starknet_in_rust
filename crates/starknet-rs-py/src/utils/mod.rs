pub mod transaction_hash;

use crate::types::general_config::PyStarknetGeneralConfig;
use crate::{cached_state::PyCachedState, types::contract_class::PyContractClass};
use cairo_vm::felt::Felt252;
use num_bigint::BigUint;
use pyo3::{exceptions::PyValueError, pyfunction, PyResult};
use starknet_rs::business_logic::fact_state::in_memory_state_reader::InMemoryStateReader;
use starknet_rs::business_logic::state::cached_state::CachedState;
use starknet_rs::core::block_hash::starknet_block_hash::calculate_event_hash;
use starknet_rs::hash_utils::calculate_contract_address;
use starknet_rs::utils::Address;
use starknet_rs::{
    business_logic::transaction::fee::calculate_tx_fee,
    core::contract_address::starknet_contract_address::compute_deprecated_class_hash,
    utils::validate_contract_deployed,
};
use std::collections::HashMap;

#[pyfunction(name = "calculate_tx_fee")]
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

#[pyfunction(name = "compute_deprecated_class_hash")]
pub(crate) fn py_compute_deprecated_class_hash(
    contract_class: &PyContractClass,
) -> PyResult<BigUint> {
    match compute_deprecated_class_hash(contract_class.into()) {
        Ok(res) => Ok(res.to_biguint()),
        Err(err) => Err(PyValueError::new_err(err.to_string())),
    }
}

// TODO: this may need to accept &impl State
#[pyfunction(name = "validate_contract_deployed")]
pub(crate) fn py_validate_contract_deployed(
    state: &mut PyCachedState,
    contract_address: BigUint,
) -> PyResult<[u8; 32]> {
    let s: &mut CachedState<InMemoryStateReader> = state.into();
    match validate_contract_deployed(s, &Address(Felt252::from(contract_address))) {
        Ok(res) => Ok(res),
        Err(err) => Err(PyValueError::new_err(err.to_string())),
    }
}

#[pyfunction(name = "calculate_event_hash")]
pub(crate) fn py_calculate_event_hash(
    from_address: BigUint,
    keys: Vec<BigUint>,
    data: Vec<BigUint>,
) -> PyResult<BigUint> {
    let felt_keys = keys.into_iter().map(Into::into).collect();
    let felt_data = data.into_iter().map(Into::into).collect();
    match calculate_event_hash(Felt252::from(from_address), felt_keys, felt_data) {
        Ok(res) => Ok(res.to_biguint()),
        Err(err) => Err(PyValueError::new_err(err.to_string())),
    }
}

#[pyfunction(name = "calculate_contract_address")]
pub(crate) fn py_calculate_contract_address(
    salt: BigUint,
    contract_class: &PyContractClass,
    constructor_calldata: Vec<BigUint>,
    deployer_address: BigUint,
) -> PyResult<BigUint> {
    let salt = Address(Felt252::from(salt));
    let class_hash = Felt252::from(py_compute_deprecated_class_hash(contract_class)?);
    let constructor_calldata: Vec<_> = constructor_calldata.into_iter().map(Into::into).collect();
    let deployer_address = Address(Felt252::from(deployer_address));
    match calculate_contract_address(&salt, &class_hash, &constructor_calldata, deployer_address) {
        Ok(res) => Ok(res.to_biguint()),
        Err(err) => Err(PyValueError::new_err(err.to_string())),
    }
}

#[pyfunction(name = "calculate_contract_address_from_hash")]
pub(crate) fn py_calculate_contract_address_from_hash(
    salt: BigUint,
    class_hash: BigUint,
    constructor_calldata: Vec<BigUint>,
    deployer_address: BigUint,
) -> PyResult<BigUint> {
    let salt = Address(Felt252::from(salt));
    let class_hash = Felt252::from(class_hash);
    let constructor_calldata: Vec<_> = constructor_calldata.into_iter().map(Into::into).collect();
    let deployer_address = Address(Felt252::from(deployer_address));
    match calculate_contract_address(&salt, &class_hash, &constructor_calldata, deployer_address) {
        Ok(res) => Ok(res.to_biguint()),
        Err(err) => Err(PyValueError::new_err(err.to_string())),
    }
}
