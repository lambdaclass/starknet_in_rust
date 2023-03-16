#![deny(warnings)]

use self::types::{
    block_info::PyBlockInfo, call_info::PyCallInfo, execution_resources::PyExecutionResources,
    ordered_event::PyOrderedEvent, ordered_l2_to_l1_message::PyOrderedL2ToL1Message,
};
use pyo3::prelude::*;

pub mod types;

#[pymodule]
pub fn starknet_rs(_py: Python, m: &PyModule) -> PyResult<()> {
    m.add_class::<PyBlockInfo>()?;
    m.add_class::<PyCallInfo>()?;
    m.add_class::<PyExecutionResources>()?;
    m.add_class::<PyOrderedEvent>()?;
    m.add_class::<PyOrderedL2ToL1Message>()?;

    Ok(())
}
