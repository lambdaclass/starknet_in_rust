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
    #[getter]
    fn name(&self) -> String {
        self.inner.to_string()
    }

    #[getter]
    fn value(&self) -> BigUint {
        self.inner.to_felt().to_biguint()
    }
}
