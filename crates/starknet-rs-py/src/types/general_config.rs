use cairo_felt::Felt252;
use num_bigint::BigUint;
use pyo3::{prelude::*, types::PyDict};
use starknet_rs::{
    business_logic::state::state_api_objects::BlockInfo,
    definitions::{
        constants::{
            DEFAULT_CAIRO_RESOURCE_FEE_WEIGHTS, DEFAULT_CONTRACT_STORAGE_COMMITMENT_TREE_HEIGHT,
            DEFAULT_GAS_PRICE, DEFAULT_GLOBAL_STATE_COMMITMENT_TREE_HEIGHT,
            DEFAULT_INVOKE_TX_MAX_N_STEPS, DEFAULT_SEQUENCER_ADDRESS, DEFAULT_STARKNET_OS_CONFIG,
            DEFAULT_VALIDATE_MAX_N_STEPS,
        },
        general_config::{StarknetChainId, StarknetGeneralConfig, StarknetOsConfig},
    },
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
        starknet_os_config = DEFAULT_STARKNET_OS_CONFIG.clone().into(),
        contract_storage_commitment_tree_height = DEFAULT_CONTRACT_STORAGE_COMMITMENT_TREE_HEIGHT,
        global_state_commitment_tree_height = DEFAULT_GLOBAL_STATE_COMMITMENT_TREE_HEIGHT,
        invoke_tx_max_n_steps = DEFAULT_INVOKE_TX_MAX_N_STEPS,
        validate_max_n_steps = DEFAULT_VALIDATE_MAX_N_STEPS,
        sequencer_address = DEFAULT_SEQUENCER_ADDRESS.0.to_biguint(),
        cairo_resource_fee_weights = DEFAULT_CAIRO_RESOURCE_FEE_WEIGHTS.clone(),
        **_kwds, // this ignores unused parameters
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
            BlockInfo::empty(Address(Felt252::from(sequencer_address))),
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
    fn invoke_tx_max_n_steps(&self) -> u64 {
        self.inner.invoke_tx_max_n_steps()
    }

    #[getter]
    fn contract_storage_commitment_tree_height(&self) -> u64 {
        self.inner.contract_storage_commitment_tree_height()
    }

    #[getter]
    fn global_state_commitment_tree_height(&self) -> u64 {
        self.inner.global_state_commitment_tree_height()
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
    fn min_gas_price(&self) -> u64 {
        DEFAULT_GAS_PRICE
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

impl From<StarknetOsConfig> for PyStarknetOsConfig {
    fn from(inner: StarknetOsConfig) -> Self {
        Self { inner }
    }
}

#[pymethods]
impl PyStarknetOsConfig {
    #[new]
    #[pyo3(signature = (
        chain_id = PyStarknetChainId::testnet(),
        fee_token_address = DEFAULT_STARKNET_OS_CONFIG.fee_token_address().0.to_biguint(),
    ))]
    fn new(chain_id: PyStarknetChainId, fee_token_address: BigUint) -> Self {
        let address = Address(Felt252::from(fee_token_address));
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
    pub fn testnet() -> Self {
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

#[cfg(test)]
mod tests {
    use super::*;
    use pyo3::{types::IntoPyDict, PyTypeInfo, Python};

    #[test]
    fn test_constructors() {
        Python::with_gil(|py| {
            let general_config_cls = <PyStarknetGeneralConfig as PyTypeInfo>::type_object(py);
            let os_config_cls = <PyStarknetOsConfig as PyTypeInfo>::type_object(py);

            // Declare classes in local scope
            let locals = [
                ("StarknetGeneralConfig", general_config_cls),
                ("StarknetOsConfig", os_config_cls),
            ]
            .into_py_dict(py);

            // Example of how StarknetGeneralConfig::new and StarknetOsConfig::new would
            // be initialized in python code. Their constructors accept as arguments any subset of
            // all parameters.
            let code = r#"
StarknetGeneralConfig()
StarknetGeneralConfig(StarknetOsConfig())
StarknetGeneralConfig(validate_max_n_steps=5)
StarknetOsConfig(fee_token_address=1337)
"#;
            let res = py.run(code, None, Some(locals));

            assert!(res.is_ok(), "{res:?}");
        });
    }
}
