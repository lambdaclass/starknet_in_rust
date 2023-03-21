#![deny(warnings)]

use self::{
    cached_state::PyCachedState,
    types::{
        block_info::PyBlockInfo, call_info::PyCallInfo, contract_class::PyContractClass,
        contract_entry_point::PyContractEntryPoint, execution_resources::PyExecutionResources,
        ordered_event::PyOrderedEvent, ordered_l2_to_l1_message::PyOrderedL2ToL1Message,
    },
};
use pyo3::prelude::*;
use starknet_state::PyStarknetState;
use types::general_config::{PyStarknetChainId, PyStarknetGeneralConfig, PyStarknetOsConfig};

mod cached_state;
mod starknet_state;
mod types;

#[pymodule]
pub fn starknet_rs_py(_py: Python, m: &PyModule) -> PyResult<()> {
    m.add_class::<PyStarknetState>()?;
    m.add_class::<PyStarknetGeneralConfig>()?;
    m.add_class::<PyStarknetOsConfig>()?;
    m.add_class::<PyStarknetChainId>()?;
    m.add_class::<PyBlockInfo>()?;
    m.add_class::<PyCachedState>()?;
    m.add_class::<PyCallInfo>()?;
    m.add_class::<PyContractClass>()?;
    m.add_class::<PyContractEntryPoint>()?;
    m.add_class::<PyExecutionResources>()?;
    m.add_class::<PyOrderedEvent>()?;
    m.add_class::<PyOrderedL2ToL1Message>()?;

    Ok(())
}
