use cairo_vm::felt::Felt252;
use num_bigint::BigUint;
use pyo3::{
    exceptions::PyKeyError,
    prelude::*,
    types::{PyDict, PyType},
};
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

#[pyclass(name = "StarknetGeneralConfig")]
#[derive(Debug, Default, Clone)]
pub struct PyStarknetGeneralConfig {
    pub(crate) inner: StarknetGeneralConfig,
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

impl<'a> From<&'a PyStarknetGeneralConfig> for &'a StarknetGeneralConfig {
    fn from(value: &'a PyStarknetGeneralConfig) -> Self {
        &value.inner
    }
}

impl From<StarknetGeneralConfig> for PyStarknetGeneralConfig {
    fn from(inner: StarknetGeneralConfig) -> Self {
        Self { inner }
    }
}

#[pyclass(name = "StarknetOsConfig")]
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
        chain_id = PyStarknetChainId::TestNet,
        fee_token_address = DEFAULT_STARKNET_OS_CONFIG.fee_token_address().0.to_biguint(),
    ))]
    fn new(chain_id: PyStarknetChainId, fee_token_address: BigUint) -> Self {
        let address = Address(Felt252::from(fee_token_address));
        let inner = StarknetOsConfig::new(chain_id.into(), address, 0);
        Self { inner }
    }
}

impl From<PyStarknetGeneralConfig> for StarknetGeneralConfig {
    fn from(pyconfig: PyStarknetGeneralConfig) -> Self {
        pyconfig.inner
    }
}

#[pyclass(name = "StarknetChainId")]
#[derive(Debug, Clone, Copy)]
pub enum PyStarknetChainId {
    #[pyo3(name = "MAINNET")]
    MainNet,
    #[pyo3(name = "TESTNET")]
    TestNet,
    #[pyo3(name = "TESTNET2")]
    TestNet2,
}

impl From<StarknetChainId> for PyStarknetChainId {
    fn from(chain_id: StarknetChainId) -> Self {
        match chain_id {
            StarknetChainId::MainNet => Self::MainNet,
            StarknetChainId::TestNet => Self::TestNet,
            StarknetChainId::TestNet2 => Self::TestNet2,
        }
    }
}

impl From<PyStarknetChainId> for StarknetChainId {
    fn from(chain_id: PyStarknetChainId) -> Self {
        match chain_id {
            PyStarknetChainId::MainNet => Self::MainNet,
            PyStarknetChainId::TestNet => Self::TestNet,
            PyStarknetChainId::TestNet2 => Self::TestNet2,
        }
    }
}

// TODO: remove impl when pyo3 adds Enum subclassing
// https://github.com/PyO3/pyo3/issues/2887
#[pymethods]
impl PyStarknetChainId {
    #[getter]
    fn name(&self) -> &str {
        match self {
            PyStarknetChainId::MainNet => "MAINNET",
            PyStarknetChainId::TestNet => "TESTNET",
            PyStarknetChainId::TestNet2 => "TESTNET2",
        }
    }

    #[getter]
    fn value(&self) -> BigUint {
        let chain_id: StarknetChainId = (*self).into();
        chain_id.to_felt().to_biguint()
    }

    // __iter__
    #[classmethod]
    fn variants(_cls: &PyType) -> Vec<Self> {
        vec![Self::MainNet, Self::TestNet, Self::TestNet2]
    }

    // __getitem__
    #[classmethod]
    fn get(_cls: &PyType, s: &str) -> PyResult<Self> {
        match s {
            "MAINNET" => Ok(PyStarknetChainId::MainNet),
            "TESTNET" => Ok(PyStarknetChainId::TestNet),
            "TESTNET2" => Ok(PyStarknetChainId::TestNet2),
            _ => Err(PyKeyError::new_err(s.to_string())),
        }
    }
}

#[pyfunction]
pub fn build_general_config(_raw_general_config: &PyDict) -> PyResult<PyStarknetGeneralConfig> {
    // TODO: this function should parse the _raw_general_config
    Ok(PyStarknetGeneralConfig::default())
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
