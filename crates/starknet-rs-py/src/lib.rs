#![deny(warnings)]

use self::cached_state::CachedState;
use pyo3::prelude::*;

mod cached_state;
mod starknet_state;

#[pymodule]
pub fn starknet_rs(_py: Python, m: &PyModule) -> PyResult<()> {
    m.add_class::<CachedState>()?;

    Ok(())
}
