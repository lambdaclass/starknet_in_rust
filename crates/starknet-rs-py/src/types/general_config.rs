// TODO: remove when pyo3 v0.18.2 releases (https://github.com/PyO3/pyo3/pull/3028)
#![allow(clippy::redundant_closure)]

use cairo_felt::Felt;
use num_bigint::BigUint;
use pyo3::{prelude::*, types::PyDict};
use starknet_rs::{
    business_logic::state::state_api_objects::BlockInfo,
    definitions::general_config::{StarknetChainId, StarknetGeneralConfig, StarknetOsConfig},
    utils::Address,
};
use std::collections::HashMap;

#[pyclass]
#[pyo3(name = "StarknetGeneralConfig")]
#[derive(Debug, Default)]
pub struct PyStarknetGeneralConfig {
    inner: StarknetGeneralConfig,
}

#[pymethods]
impl PyStarknetGeneralConfig {
    #[new]
    #[pyo3(signature = (
        starknet_os_config = Default::default(),
        contract_storage_commitment_tree_height = Default::default(),
        global_state_commitment_tree_height = Default::default(),
        invoke_tx_max_n_steps = Default::default(),
        validate_max_n_steps = Default::default(),
        sequencer_address = Default::default(),
        cairo_resource_fee_weights = Default::default(),
        **_kwds,
    ))]
    #[allow(clippy::too_many_arguments)]
    fn new(
        starknet_os_config: PyStarknetOsConfig,
        contract_storage_commitment_tree_height: u64,
        global_state_commitment_tree_height: u64,
        invoke_tx_max_n_steps: u64,
        validate_max_n_steps: u64,
        sequencer_address: BigUint,
        cairo_resource_fee_weights: HashMap<String, f64>,
        _kwds: Option<&PyDict>,
    ) -> Self {
        let inner = StarknetGeneralConfig::new(
            starknet_os_config.into(),
            contract_storage_commitment_tree_height,
            global_state_commitment_tree_height,
            cairo_resource_fee_weights,
            invoke_tx_max_n_steps,
            validate_max_n_steps,
            BlockInfo::empty(Address(Felt::from(sequencer_address))),
        );
        Self { inner }
    }

    #[getter]
    fn chain_id(&self) -> PyStarknetChainId {
        (*self.inner.starknet_os_config().chain_id()).into()
    }

    #[getter]
    fn fee_token_address(&self) -> BigUint {
        self.inner
            .starknet_os_config()
            .fee_token_address()
            .0
            .to_biguint()
    }

    #[getter]
    fn sequencer_address(&self) -> BigUint {
        self.inner.block_info().sequencer_address.0.to_biguint()
    }

    #[getter]
    fn min_gas_price(&self) -> u64 {
        todo!()
    }

    #[getter]
    fn invoke_tx_max_n_steps(&self) -> u64 {
        self.inner.invoke_tx_max_n_steps()
    }

    #[getter]
    fn contract_storage_commitment_tree_height(&self) -> u64 {
        self.inner._contract_storage_commitment_tree_height()
    }

    #[getter]
    fn global_state_commitment_tree_height(&self) -> u64 {
        self.inner._global_state_commitment_tree_height()
    }

    #[getter]
    fn cairo_resource_fee_weights(&self) -> HashMap<String, f64> {
        self.inner.cairo_resource_fee_weights().clone()
    }

    #[getter]
    fn validate_max_n_steps(&self) -> u64 {
        self.inner.validate_max_n_steps()
    }

    #[getter]
    fn event_commitment_tree_height(&self) -> u64 {
        todo!()
    }

    #[getter]
    fn tx_commitment_tree_height(&self) -> u64 {
        todo!()
    }
}

#[pyclass]
#[pyo3(name = "StarknetOsConfig")]
#[derive(Debug, Clone, Default)]
pub struct PyStarknetOsConfig {
    inner: StarknetOsConfig,
}

impl From<PyStarknetOsConfig> for StarknetOsConfig {
    fn from(config: PyStarknetOsConfig) -> Self {
        config.inner
    }
}

#[pymethods]
impl PyStarknetOsConfig {
    #[new]
    #[pyo3(signature = (
        chain_id = PyStarknetChainId::testnet(),
        fee_token_address = Default::default(),
    ))]
    fn new(chain_id: PyStarknetChainId, fee_token_address: BigUint) -> Self {
        let address = Address(Felt::from(fee_token_address));
        let inner = StarknetOsConfig::new(chain_id.into(), address, 0);
        Self { inner }
    }
}

#[pyclass]
#[pyo3(name = "StarknetChainId")]
#[derive(Debug, Clone, Copy)]
pub struct PyStarknetChainId {
    inner: StarknetChainId,
}

impl From<StarknetChainId> for PyStarknetChainId {
    fn from(inner: StarknetChainId) -> Self {
        Self { inner }
    }
}

impl From<PyStarknetChainId> for StarknetChainId {
    fn from(chain_id: PyStarknetChainId) -> Self {
        chain_id.inner
    }
}

#[pymethods]
impl PyStarknetChainId {
    #[classattr]
    #[pyo3(name = "MAINNET")]
    fn mainnet() -> Self {
        Self {
            inner: StarknetChainId::MainNet,
        }
    }

    #[classattr]
    #[pyo3(name = "TESTNET")]
    fn testnet() -> Self {
        Self {
            inner: StarknetChainId::TestNet,
        }
    }

    #[classattr]
    #[pyo3(name = "TESTNET2")]
    fn testnet2() -> Self {
        Self {
            inner: StarknetChainId::TestNet2,
        }
    }

    #[getter]
    fn name(&self) -> String {
        self.inner.to_string()
    }

    #[getter]
    fn value(&self) -> BigUint {
        self.inner.to_felt().to_biguint()
    }
}
