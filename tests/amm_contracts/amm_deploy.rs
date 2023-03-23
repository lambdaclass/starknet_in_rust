use cairo_rs::vm::runners::cairo_runner::ExecutionResources;
use felt::Felt;
use starknet_rs::{
    business_logic::{
        execution::objects::{CallInfo, CallType},
        fact_state::{
            in_memory_state_reader::InMemoryStateReader, state::ExecutionResourcesManager,
        },
        state::cached_state::CachedState,
        transaction::error::TransactionError,
    },
    definitions::general_config::StarknetGeneralConfig,
    services::api::contract_class::EntryPointType,
    utils::{calculate_sn_keccak, Address},
};

use crate::amm_contracts::utils::*;

fn init_pool(
    calldata: &[Felt],
    call_config: &mut CallConfig,
) -> Result<CallInfo, TransactionError> {
    execute_entry_point("init_pool", calldata, call_config)
}

#[test]
fn amm_init_pool_test() {
    let general_config = StarknetGeneralConfig::default();
    let state_reader = InMemoryStateReader::default();
    let mut state = CachedState::new(state_reader, Some(Default::default()));
    // Deploy contract
    let (contract_address, class_hash) =
        deploy(&mut state, "starknet_programs/amm.json", &general_config);

    let calldata = [10000.into(), 10000.into()].to_vec();
    let caller_address = Address(0000.into());
    let mut resources_manager = ExecutionResourcesManager::default();

    let amm_entrypoint_selector = Felt::from_bytes_be(&calculate_sn_keccak(b"init_pool"));

    let accessed_storage_keys =
        get_accessed_keys("pool_balance", vec![vec![1_u8.into()], vec![2_u8.into()]]);

    let expected_call_info = CallInfo {
        caller_address: Address(0.into()),
        call_type: Some(CallType::Delegate),
        contract_address: contract_address.clone(),
        entry_point_selector: Some(amm_entrypoint_selector),
        entry_point_type: Some(EntryPointType::External),
        calldata: calldata.clone(),
        retdata: [].to_vec(),
        execution_resources: ExecutionResources::default(),
        class_hash: Some(class_hash),
        accessed_storage_keys,
        ..Default::default()
    };

    let mut call_config = CallConfig {
        state: &mut state,
        caller_address: &caller_address,
        address: &contract_address,
        class_hash: &class_hash,
        general_config: &general_config,
        resources_manager: &mut resources_manager,
    };

    assert_eq!(
        init_pool(&calldata, &mut call_config).unwrap(),
        expected_call_info
    );
}
