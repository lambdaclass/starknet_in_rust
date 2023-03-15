#![deny(warnings)]

use pyo3::prelude::*;
use types::{
    block_info::PyBlockInfo,
    general_config::{PyStarknetGeneralConfig, PyStarknetOsConfig},
};

pub mod types;

#[pymodule]
pub fn starknet_rs(_py: Python, m: &PyModule) -> PyResult<()> {
    m.add_class::<PyStarknetGeneralConfig>()?;
    m.add_class::<PyStarknetOsConfig>()?;
    m.add_class::<PyBlockInfo>()
}
