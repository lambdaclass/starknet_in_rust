#![deny(warnings)]

mod cached_state;
mod starknet_state;
mod types;

use self::{
    cached_state::PyCachedState,
    types::{
        block_info::PyBlockInfo, call_info::PyCallInfo, contract_class::PyContractClass,
        contract_entry_point::PyContractEntryPoint, execution_resources::PyExecutionResources,
        ordered_event::PyOrderedEvent, ordered_l2_to_l1_message::PyOrderedL2ToL1Message,
    },
};
use pyo3::prelude::*;
use types::general_config::{PyStarknetChainId, PyStarknetGeneralConfig, PyStarknetOsConfig};

#[cfg(all(feature = "extension-module", feature = "embedded-python"))]
compile_error!("\"extension-module\" is incompatible with \"embedded-python\" as it inhibits linking with cpython");

#[pymodule]
pub fn starknet_rs_py(_py: Python, m: &PyModule) -> PyResult<()> {
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

#[cfg(test)]
mod test {
    use pyo3::prelude::*;

    #[test]
    fn starknet_rs_py_test() {
        Python::with_gil(|py| {
            let module = PyModule::new(py, "My Module");
            assert!(crate::starknet_rs_py(py, module.unwrap()).is_ok());
        });
    }
}
