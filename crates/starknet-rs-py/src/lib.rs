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
use crate::{
    types::{
        contract_entry_point::PyEntryPointType,
        general_config::build_general_config,
        starknet_message_to_l1::PyStarknetMessageToL1,
        transaction::{PyTransaction, PyTransactionType},
        transaction_execution_info::PyTransactionExecutionInfo,
        transactions::{
            declare::PyInternalDeclare, deploy::PyInternalDeploy,
            deploy_account::PyInternalDeployAccount, invoke_function::PyInternalInvokeFunction,
        },
    },
    utils::{
        py_calculate_contract_address, py_calculate_contract_address_from_hash,
        py_calculate_event_hash, py_calculate_tx_fee, py_compute_class_hash,
        py_validate_contract_deployed,
        transaction_hash::{
            py_calculate_declare_transaction_hash, py_calculate_deploy_transaction_hash,
            py_calculate_transaction_hash_common, PyTransactionHashPrefix,
        },
    },
};
use cairo_felt::{felt_str, Felt252};
use pyo3::prelude::*;
use starknet_rs::{
    business_logic::state::cached_state::UNINITIALIZED_CLASS_HASH,
    definitions::constants::{
        DEFAULT_CONTRACT_STORAGE_COMMITMENT_TREE_HEIGHT, DEFAULT_GAS_PRICE,
        DEFAULT_SEQUENCER_ADDRESS, DEFAULT_VALIDATE_MAX_N_STEPS, TRANSACTION_VERSION,
    },
};
use starknet_state::PyStarknetState;
use std::ops::Shl;
use types::general_config::{PyStarknetChainId, PyStarknetGeneralConfig, PyStarknetOsConfig};

#[cfg(all(feature = "extension-module", feature = "embedded-python"))]
compile_error!("\"extension-module\" is incompatible with \"embedded-python\" as it inhibits linking with cpython");

#[pymodule]
#[pyo3(name = "starknet_rs_py")]
pub fn starknet_rs_py(_py: Python, m: &PyModule) -> PyResult<()> {
    eprintln!("WARN: using starknet_rs_py");

    // ~~~~~~~~~~~~~~~~~~~~
    //  Exported Classes
    // ~~~~~~~~~~~~~~~~~~~~

    m.add_class::<PyStarknetState>()?;
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
    m.add_class::<PyTransactionHashPrefix>()?;
    m.add_class::<PyTransaction>()?;
    m.add_class::<PyTransactionType>()?;
    m.add_class::<PyStarknetMessageToL1>()?;
    m.add_class::<PyTransactionExecutionInfo>()?;
    m.add_class::<PyInternalDeclare>()?;
    m.add_class::<PyInternalDeploy>()?;
    m.add_class::<PyInternalDeployAccount>()?;
    m.add_class::<PyInternalInvokeFunction>()?;

    m.add_class::<PyEntryPointType>()?;

    // ~~~~~~~~~~~~~~~~~~~~
    //  Exported Functions
    // ~~~~~~~~~~~~~~~~~~~~

    m.add_function(wrap_pyfunction!(build_general_config, m)?)?;
    m.add_function(wrap_pyfunction!(py_calculate_transaction_hash_common, m)?)?;
    m.add_function(wrap_pyfunction!(py_calculate_declare_transaction_hash, m)?)?;
    m.add_function(wrap_pyfunction!(py_calculate_deploy_transaction_hash, m)?)?;
    m.add_function(wrap_pyfunction!(
        py_calculate_contract_address_from_hash,
        m
    )?)?;
    m.add_function(wrap_pyfunction!(py_calculate_contract_address, m)?)?;
    m.add_function(wrap_pyfunction!(py_calculate_event_hash, m)?)?;
    m.add_function(wrap_pyfunction!(py_validate_contract_deployed, m)?)?;
    m.add_function(wrap_pyfunction!(py_compute_class_hash, m)?)?;
    m.add_function(wrap_pyfunction!(py_calculate_tx_fee, m)?)?;

    // This function initializes the module's reexports
    m.add_function(wrap_pyfunction!(add_reexports, m)?)?;

    // ~~~~~~~~~~~~~~~~~~~~
    //  Exported Constants
    // ~~~~~~~~~~~~~~~~~~~~

    m.add("DEFAULT_GAS_PRICE", DEFAULT_GAS_PRICE)?;

    // in cairo-lang they're equal
    m.add("DEFAULT_MAX_STEPS", DEFAULT_VALIDATE_MAX_N_STEPS)?;
    m.add("DEFAULT_VALIDATE_MAX_STEPS", DEFAULT_VALIDATE_MAX_N_STEPS)?;

    m.add("DEFAULT_CHAIN_ID", PyStarknetChainId::TestNet)?;
    m.add(
        "DEFAULT_SEQUENCER_ADDRESS",
        DEFAULT_SEQUENCER_ADDRESS.0.to_biguint(),
    )?;

    // The sender address used by default in declare transactions of version 0.
    m.add(
        "DEFAULT_DECLARE_SENDER_ADDRESS",
        Felt252::from(1).to_biguint(),
    )?;

    // OS context offset.
    m.add("SYSCALL_PTR_OFFSET", Felt252::from(0).to_biguint())?;

    // open_zeppelin's account contract
    m.add(
        "account_contract",
        PyContractClass::try_from(include_str!("../../../starknet_programs/Account.json"))
            .expect("program couldn't be parsed"),
    )?;

    m.add("LATEST_BLOCK_ID", "latest")?;
    m.add("PENDING_BLOCK_ID", "pending")?;

    m.add(
        "FAULTY_CLASS_HASH",
        felt_str!("748273551117330086452242911863358006088276559700222288674638023319407008063")
            .to_biguint(),
    )?;

    m.add("UNINITIALIZED_CLASS_HASH", *UNINITIALIZED_CLASS_HASH)?;

    // Indentation for transactions meant to query and not addressed to the OS.
    let query_version_base = Felt252::from(1).shl(128u32); // == 2 ** 128
    let query_version = query_version_base + Felt252::from(TRANSACTION_VERSION);
    m.add("QUERY_VERSION", query_version.to_biguint())?;

    m.add("TRANSACTION_VERSION", TRANSACTION_VERSION)?;

    // The (empirical) L1 gas cost of each Cairo step.
    pub const N_STEPS_FEE_WEIGHT: f64 = 0.05;
    m.add("N_STEPS_FEE_WEIGHT", N_STEPS_FEE_WEIGHT)?;

    m.add(
        "CONTRACT_STATES_COMMITMENT_TREE_HEIGHT",
        DEFAULT_CONTRACT_STORAGE_COMMITMENT_TREE_HEIGHT,
    )?;

    m.add("EVENT_COMMITMENT_TREE_HEIGHT", 64)?;
    m.add("TRANSACTION_COMMITMENT_TREE_HEIGHT", 64)?;

    // Felt252 number of bits
    m.add("CONTRACT_ADDRESS_BITS", 251)?;

    Ok(())
}

/// Initializes reexported module attributes.
// NOTE: this is needed to avoid circular dependencies because of the monkeypatch.
#[pyfunction(name = "init")]
pub fn add_reexports(py: Python, opt_m: Option<&PyModule>) -> PyResult<()> {
    // It's Option<_> to avoid having to pass the module in Python
    let m = match opt_m {
        Some(module) => module,
        None => PyModule::import(py, "starknet_rs_py")?,
    };

    // ~~~~~~~~~~~~
    //  Reexported
    // ~~~~~~~~~~~~
    reexport(
        py,
        m,
        "starkware.starknet.definitions.error_codes",
        vec!["StarknetErrorCode"],
    )?;

    reexport(
        py,
        m,
        "starkware.starknet.services.api.gateway.transaction",
        vec![
            "AccountTransaction",
            "Declare",
            "DeployAccount",
            "InvokeFunction",
            "Deploy",
        ],
    )?;

    reexport(
        py,
        m,
        "starkware.starknet.services.api.feeder_gateway.response_objects",
        vec![
            "DeployedContract",
            "FeeEstimationInfo",
            "StorageEntry",    // alias Tuple[int, int]
            "BlockIdentifier", // Union[int, Literal["latest"], Literal["pending"]]
            "StateDiff",
            "BlockStateUpdate",
            "BlockStatus",
            "BlockTransactionTraces",
            "TransactionSimulationInfo",
            "StarknetBlock",
            "TransactionInfo",
            "TransactionReceipt",
            "TransactionStatus",
            "TransactionTrace",
            "TransactionExecution",
            "TransactionSpecificInfo",
            "Event",
            "FunctionInvocation",
            "L2ToL1Message",
            "DeclareSpecificInfo",
            "DeployAccountSpecificInfo",
            "DeploySpecificInfo",
            "InvokeSpecificInfo",
            "L1HandlerSpecificInfo",
        ],
    )?;

    reexport(
        py,
        m,
        "starkware.starknet.services.api.feeder_gateway.request_objects",
        vec!["CallL1Handler", "CallFunction"],
    )?;

    reexport(
        py,
        m,
        "starkware.starknet.services.api.feeder_gateway.feeder_gateway_client",
        vec!["FeederGatewayClient"],
    )?;

    reexport(
        py,
        m,
        "starkware.starknet.testing.starknet",
        vec!["Starknet", "StarknetCallInfo"],
    )?;

    reexport(
        py,
        m,
        "starkware.starknet.business_logic.execution.objects",
        vec!["ResourcesMapping"],
    )?;

    reexport(
        py,
        m,
        "starkware.starknet.business_logic.state.state_api",
        vec!["SyncState", "StateReader"],
    )?;

    reexport(
        py,
        m,
        "starkware.starknet.testing.contract",
        vec!["StarknetContract"],
    )?;

    reexport(
        py,
        m,
        "starkware.starknet.business_logic.transaction.objects",
        vec![
            "InternalAccountTransaction",
            "InternalTransaction",
            "InternalL1Handler", // TODO: export from starknet-rs when implemented
        ],
    )?;

    reexport(
        py,
        m,
        "starkware.starknet.wallets.open_zeppelin",
        vec!["sign_deploy_account_tx", "sign_invoke_tx"],
    )?;

    reexport(
        py,
        m,
        "starkware.starknet.public.abi",
        vec![
            "AbiEntryType", // alias Dict[str, Any]
            // TODO: export from starknet-rs when implemented
            "get_selector_from_name",
            "get_storage_var_address",
        ],
    )?;

    // TODO: export from starknet-rs when implemented
    reexport(
        py,
        m,
        "starkware.starknet.core.os.block_hash.block_hash",
        vec!["calculate_block_hash"],
    )?;

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
    use super::*;

    #[test]
    fn starknet_rs_py_test() {
        Python::with_gil(|py| {
            // try loading our module
            let module = PyModule::new(py, "My Module");
            let res = crate::starknet_rs_py(py, module.unwrap());
            assert!(res.is_ok(), "{res:?}");
        });
    }

    #[test]
    fn starknet_rs_py_add_reexports() {
        Python::with_gil(|py| {
            // try loading our module
            let m = PyModule::new(py, "starknet_rs_py").unwrap();

            starknet_rs_py(py, &m).unwrap();

            let res = m.get_item("StarknetErrorCode");

            assert!(res.is_err(), "{res:?}");

            add_reexports(py, Some(m)).unwrap();

            let res = m.get_item("StarknetErrorCode");

            assert!(res.is_err(), "{res:?}");
        });
    }
}
