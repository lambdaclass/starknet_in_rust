use pyo3::prelude::*;
use starknet_rs::business_logic::state::state_api_objects::BlockInfo;

#[pyclass]
pub struct PyBlockInfo {
    _inner: BlockInfo,
}
