#![deny(warnings)]

mod cached_state;
mod starknet_state;
mod types;
mod utils;

use self::{
    cached_state::PyCachedState,
    types::{
        block_info::PyBlockInfo, call_info::PyCallInfo, contract_class::PyContractClass,
        contract_entry_point::PyContractEntryPoint, execution_resources::PyExecutionResources,
        ordered_event::PyOrderedEvent, ordered_l2_to_l1_message::PyOrderedL2ToL1Message,
    },
};
use crate::utils::{py_calculate_tx_fee, py_compute_class_hash, py_validate_contract_deployed};
use pyo3::prelude::*;
use types::general_config::{PyStarknetChainId, PyStarknetGeneralConfig, PyStarknetOsConfig};

#[cfg(all(feature = "extension-module", feature = "embedded-python"))]
compile_error!("\"extension-module\" is incompatible with \"embedded-python\" as it inhibits linking with cpython");

#[pymodule]
pub fn starknet_rs_py(py: Python, m: &PyModule) -> PyResult<()> {
    eprintln!("WARN: using starknet_rs_py");
    // starkware.starknet.business_logic.state.state
    m.add_class::<PyBlockInfo>()?;
    m.add_class::<PyCachedState>()?;

    m.add_class::<PyStarknetGeneralConfig>()?;
    m.add_class::<PyStarknetOsConfig>()?;
    m.add_class::<PyStarknetChainId>()?;
    m.add_class::<PyContractClass>()?;
    m.add_class::<PyContractEntryPoint>()?;
    m.add_class::<PyExecutionResources>()?;
    m.add_class::<PyOrderedEvent>()?;
    m.add_class::<PyOrderedL2ToL1Message>()?;
    m.add_class::<PyCallInfo>()?;

    //  starkware.starknet.core.os.transaction_hash.transaction_hash
    // m.add_class::<PyTransactionHashPrefix>()?;
    // m.add_function(calculate_declare_transaction_hash)?;
    // m.add_function(calculate_deploy_transaction_hash)?;
    // m.add_function(calculate_transaction_hash_common)?;

    // m.add("DEFAULT_GAS_PRICE", value)?;
    // m.add("DEFAULT_MAX_STEPS", value)?;
    // m.add("DEFAULT_SEQUENCER_ADDRESS", value)?;
    // m.add("DEFAULT_VALIDATE_MAX_STEPS", value)?;
    // m.add("DEFAULT_CHAIN_ID", value)?;
    // m.add_function(build_general_config)?;

    //  starkware.starknet.public.abi
    // m.add_function(get_selector_from_name)?;
    // m.add("SYSCALL_PTR_OFFSET", value)?;
    // m.add_class::<PyAbiEntryType>()?;
    // m.add_function(get_storage_var_address)?;

    //  starkware.starknet.testing.starknet
    // m.add_class::<PyStarknet>()?;
    // m.add_class::<PyStarknetCallInfo>()?;

    //  starkware.starknet.testing.state
    // m.add_class::<PyStarknetState>()?;

    //  starkware.starknet.core.os.contract_address.contract_address
    // m.add_function(calculate_contract_address_from_hash)?;
    // m.add_function(calculate_contract_address)?;

    //  starkware.starknet.core.os.block_hash.block_hash
    // m.add_function(calculate_block_hash)?;
    // m.add_function(calculate_event_hash)?;

    //  starkware.starknet.definitions.error_codes
    // m.add_class::<PyStarknetErrorCode>()?;

    //  starkware.starknet.services.api.feeder_gateway.response_objects
    // m.add("LATEST_BLOCK_ID", value)?;
    // m.add("PENDING_BLOCK_ID", value)?;
    // m.add_class::<PyBlockIdentifier>()?; this one is a Python Union
    // m.add_class::<PyBlockStateUpdate>()?;
    // m.add_class::<PyBlockStatus>()?;
    // m.add_class::<PyBlockTransactionTraces>()?;
    // m.add_class::<PyTransactionSimulationInfo>()?;
    // m.add_class::<PyStarknetBlock>()?;
    // m.add_class::<PyTransactionInfo>()?;
    // m.add_class::<PyTransactionReceipt>()?;
    // m.add_class::<PyTransactionStatus>()?;
    // m.add_class::<PyTransactionTrace>()?;
    // m.add_class::<PyTransactionExecution>()?;
    // m.add_class::<PyTransactionSpecificInfo>()?;
    // m.add_class::<PyFeeEstimationInfo>()?;
    // m.add_class::<PyDeployedContract>()?;
    // m.add_class::<PyStateDiff>()?;
    // m.add_class::<PyStorageEntry>()?;
    // m.add_class::<PyEvent>()?;
    // m.add_class::<PyFunctionInvocation>()?;
    // m.add_class::<PyL2ToL1Message>()?;
    // m.add_class::<PyDeclareSpecificInfo>()?;
    // m.add_class::<PyDeployAccountSpecificInfo>()?;
    // m.add_class::<PyDeploySpecificInfo>()?;
    // m.add_class::<PyInvokeSpecificInfo>()?;
    // m.add_class::<PyL1HandlerSpecificInfo>()?;

    //  starkware.starknet.business_logic.execution.execute_entry_point
    // m.add_class::<PyExecuteEntryPoint>()?;
    // m.add("FAULTY_CLASS_HASH", value)?;

    //  starkware.starknet.business_logic.execution.objects
    // m.add_class::<PyTransactionExecutionContext>()?;
    // m.add_class::<PyResourcesMapping>()?;

    //  starkware.starknet.business_logic.fact_state.state
    // m.add_class::<PyExecutionResourcesManager>()?;

    //  starkware.starknet.business_logic.state.state_api
    // m.add_class::<PySyncState>()?;
    // m.add_class::<PyStateReader>()?;

    //  starkware.starknet.core.os.syscall_utils
    // m.add_class::<PyBusinessLogicSysCallHandler>()?;
    // m.add_class::<PyHandlerException>()?;

    //  starkware.starknet.services.api.feeder_gateway.feeder_gateway_client
    // m.add_class::<PyFeederGatewayClient>()?;

    //  starkware.starknet.services.api.gateway.transaction
    // m.add_class::<PyAccountTransaction>()?;
    // m.add_class::<PyDeclare>()?;
    // m.add_class::<PyDeployAccount>()?;
    // m.add_class::<PyInvokeFunction>()?;
    // m.add_class::<PyDeploy>()?;
    // m.add_class::<PyTransaction>()?;
    // m.add("DEFAULT_DECLARE_SENDER_ADDRESS", value)?;

    //  starkware.starknet.definitions.constants
    // m.add("UNINITIALIZED_CLASS_HASH", value)?;
    // m.add("QUERY_VERSION", value)?;
    // m.add("TRANSACTION_VERSION", value)?;
    // m.add("N_STEPS_FEE_WEIGHT", value)?;
    // m.add("CONTRACT_STATES_COMMITMENT_TREE_HEIGHT", value)?;
    // m.add("EVENT_COMMITMENT_TREE_HEIGHT", value)?;
    // m.add("CONTRACT_ADDRESS_BITS", value)?;
    // m.add("TRANSACTION_COMMITMENT_TREE_HEIGHT", value)?;

    //  starkware.starknet.business_logic.transaction.objects
    // m.add_class::<PyInternalL1Handler>()?;
    // m.add_class::<PyInternalAccountTransaction>()?;
    // m.add_class::<PyInternalDeclare>()?;
    // m.add_class::<PyInternalDeploy>()?;
    // m.add_class::<PyInternalDeployAccount>()?;
    // m.add_class::<PyInternalInvokeFunction>()?;
    // m.add_class::<PyInternalTransaction>()?;
    // m.add_class::<PyTransactionExecutionInfo>()?;

    //  starkware.starknet.testing.contract
    // m.add_class::<PyStarknetContract>()?;

    //  starkware.starknet.definitions.transaction_type
    // m.add_class::<PyTransactionType>()?;

    //  starkware.starknet.services.api.feeder_gateway.request_objects
    // m.add_class::<PyCallFunction>()?;
    // m.add_class::<PyCallL1Handler>()?;

    //  starkware.starknet.services.api.messages
    // m.add_class::<PyStarknetMessageToL1>()?;

    //  starkware.starknet.third_party.open_zeppelin.starknet_contracts
    // m.add("account_contract", value)?;

    //  starkware.starknet.wallets.open_zeppelin
    // m.add_function(sign_deploy_account_tx)?;  blocked by PyDeployAccount
    // m.add_function(sign_invoke_tx)?;          blocked by PyInvokeFunction

    //  starkware.starknet.core.os.segment_utils
    // m.add_function(get_os_segment_ptr_range)?;   need cairo-rs-py to implement CairoFunctionRunner
    // m.add_function(validate_segment_pointers)?;  needs cairo-rs-py to export PySegmentManager

    //  starkware.starknet.core.os.os_utils
    // m.add_function(prepare_os_context)?;               need cairo-rs-py to implement CairoFunctionRunner
    // m.add_function(validate_and_process_os_context)?;  need cairo-rs-py to implement CairoFunctionRunner

    m.add_function(wrap_pyfunction!(py_validate_contract_deployed, m)?)?;
    m.add_function(wrap_pyfunction!(py_compute_class_hash, m)?)?;
    m.add_function(wrap_pyfunction!(py_calculate_tx_fee, m)?)?;

    reexport(
        py,
        m,
        "starkware.starknet.business_logic.utils",
        vec!["verify_version"],
    )?;

    reexport(
        py,
        m,
        "starkware.starknet.services.api.gateway.transaction_utils",
        vec!["compress_program", "decompress_program"],
    )?;

    reexport(
        py,
        m,
        "starkware.starknet.cli.starknet_cli",
        vec!["get_salt"],
    )?;

    Ok(())
}

fn reexport(py: Python, dst: &PyModule, src_name: &str, names: Vec<&str>) -> PyResult<()> {
    let src = PyModule::import(py, src_name)?;
    for name in names {
        dst.add(name, src.getattr(name)?)?;
    }
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
