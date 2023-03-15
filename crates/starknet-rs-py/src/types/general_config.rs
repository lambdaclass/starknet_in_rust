use std::collections::HashMap;

use num_bigint::BigUint;
use pyo3::prelude::*;
use starknet_rs::definitions::general_config::{StarknetChainId, StarknetGeneralConfig};

#[pyclass]
#[pyo3(name = "StarknetGeneralConfig")]
#[derive(Debug, Default)]
pub struct PyStarknetGeneralConfig {
    inner: StarknetGeneralConfig,
}

#[pymethods]
impl PyStarknetGeneralConfig {
    #[new]
    fn new() -> Self {
        Default::default()
    }

    #[getter]
    fn chain_id(&self) -> PyStarknetChainId {
        self.inner.starknet_os_config().chain_id().clone().into()
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
        self.inner.invoke_tx_max_n_steps().into()
    }

    #[getter]
    fn contract_storage_commitment_tree_height(&self) -> u64 {
        self.inner._contract_storage_commitment_tree_height().into()
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
        self.inner.validate_max_n_steps().into()
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
#[pyo3(name = "StarknetChainId")]
#[derive(Debug)]
pub struct PyStarknetChainId {
    inner: StarknetChainId,
}

impl From<StarknetChainId> for PyStarknetChainId {
    fn from(inner: StarknetChainId) -> Self {
        Self { inner }
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
