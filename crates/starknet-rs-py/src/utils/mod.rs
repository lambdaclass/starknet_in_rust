use crate::types::general_config::PyStarknetGeneralConfig;
use crate::{cached_state::PyCachedState, types::contract_class::PyContractClass};
use cairo_felt::Felt252;
use num_bigint::BigUint;
use pyo3::{exceptions::PyValueError, pyfunction, PyResult};
use starknet_rs::business_logic::fact_state::in_memory_state_reader::InMemoryStateReader;
use starknet_rs::business_logic::state::cached_state::CachedState;
use starknet_rs::core::block_hash::starknet_block_hash::calculate_event_hash;
use starknet_rs::core::transaction_hash::starknet_transaction_hash::{
    calculate_declare_transaction_hash, calculate_deploy_transaction_hash,
};
use starknet_rs::hash_utils::calculate_contract_address;
use starknet_rs::utils::Address;
use starknet_rs::{
    business_logic::transaction::fee::calculate_tx_fee,
    core::contract_address::starknet_contract_address::compute_class_hash,
    utils::validate_contract_deployed,
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

// TODO: this may need to accept &impl State
#[pyfunction]
#[pyo3(name = "validate_contract_deployed")]
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

#[pyfunction]
#[pyo3(name = "calculate_event_hash")]
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

#[pyfunction]
#[pyo3(name = "calculate_contract_address")]
pub(crate) fn py_calculate_contract_address(
    salt: BigUint,
    contract_class: &PyContractClass,
    constructor_calldata: Vec<BigUint>,
    deployer_address: BigUint,
) -> PyResult<BigUint> {
    let salt = Address(Felt252::from(salt));
    let class_hash = Felt252::from(py_compute_class_hash(contract_class)?);
    let constructor_calldata: Vec<_> = constructor_calldata.into_iter().map(Into::into).collect();
    let deployer_address = Address(Felt252::from(deployer_address));
    match calculate_contract_address(&salt, &class_hash, &constructor_calldata, deployer_address) {
        Ok(res) => Ok(res.to_biguint()),
        Err(err) => Err(PyValueError::new_err(err.to_string())),
    }
}

#[pyfunction]
#[pyo3(name = "calculate_contract_address_from_hash")]
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
