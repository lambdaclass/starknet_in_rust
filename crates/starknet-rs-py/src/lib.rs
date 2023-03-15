#![deny(warnings)]

use pyo3::prelude::*;
use types::block_info::PyBlockInfo;

pub mod types;

#[pymodule]
pub fn starknet_rs(_py: Python, m: &PyModule) -> PyResult<()> {
    m.add_class::<PyBlockInfo>()
}
