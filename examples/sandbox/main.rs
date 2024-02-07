//! This example shows how to use the `IsolatedExecutor` cairo-native sandbox with starknet in rust.

use std::{
    fs,
    path::{Path, PathBuf},
    sync::Arc,
};

use cairo_vm::Felt252;
use starknet_in_rust::{
    definitions::{block_context::BlockContext, constants::TRANSACTION_VERSION},
    execution::{
        execution_entry_point::ExecutionEntryPoint, CallType, TransactionExecutionContext,
    },
    sandboxing::IsolatedExecutor,
    services::api::contract_classes::compiled_class::CompiledClass,
    state::{
        cached_state::CachedState,
        contract_class_cache::{ContractClassCache, PermanentContractClassCache},
        in_memory_state_reader::InMemoryStateReader,
        ExecutionResourcesManager,
    },
    utils::{felt_to_hash, Address, ClassHash},
    CasmContractClass,
};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let executor_path = std::env::var("CAIRO_NATIVE_EXECUTOR_PATH")
        .map(PathBuf::from)
        .unwrap_or_else(|_| {
            std::env::current_dir()
                .unwrap()
                .join("target/debug/cairo_native_executor")
        });
    let sandbox = IsolatedExecutor::new(executor_path.as_path())?;

    let mut state_reader = InMemoryStateReader::default();
    let cache = PermanentContractClassCache::default();

    let class_hash = ClassHash([1; 32]);
    let caller_address = Address(1.into());
    let callee_address = Address(1.into());

    let path = Path::new("starknet_programs/cairo2/get_block_hash_basic.cairo");

    let casm_contract_class_data = fs::read_to_string(path.with_extension("casm"))?;
    let sierra_contract_class_data = fs::read_to_string(path.with_extension("sierra"))?;

    let casm_contract_class: CasmContractClass = serde_json::from_str(&casm_contract_class_data)?;
    let sierra_contract_class: cairo_lang_starknet::contract_class::ContractClass =
        serde_json::from_str(&sierra_contract_class_data)?;

    let casm_contract_class = Arc::new(casm_contract_class);
    let sierra_contract_class = Arc::new((
        sierra_contract_class.extract_sierra_program().unwrap(),
        sierra_contract_class.entry_points_by_type,
    ));

    cache.set_contract_class(
        class_hash,
        CompiledClass::Casm {
            casm: casm_contract_class,
            sierra: Some(sierra_contract_class),
        },
    );

    state_reader
        .address_to_class_hash_mut()
        .insert(caller_address.clone(), class_hash);
    state_reader
        .address_to_nonce_mut()
        .insert(callee_address.clone(), Felt252::default());

    let mut state = CachedState::new(Arc::new(state_reader), Arc::new(cache));

    state.cache_mut().storage_initial_values_mut().insert(
        (Address(Felt252::ONE), felt_to_hash(&10.into()).0),
        Felt252::from_bytes_be(&[5; 32]),
    );

    let class_hash = *state
        .state_reader
        .address_to_class_hash
        .get(&caller_address)
        .unwrap();

    let mut block_context = BlockContext::default();
    block_context.block_info_mut().block_number = 30;

    let execution_result_native = ExecutionEntryPoint::new(
        callee_address.clone(),
        vec![10.into()],
        Felt252::from_hex("377ae94b690204c74c8d21938c5b72e80fdaee3d21c780fd7557a7f84a8b379")
            .unwrap(),
        caller_address.clone(),
        starknet_in_rust::EntryPointType::External,
        Some(CallType::Delegate),
        Some(class_hash),
        u128::MAX,
    )
    .execute(
        &mut state,
        &block_context,
        &mut ExecutionResourcesManager::default(),
        &mut TransactionExecutionContext::new(
            Address(Felt252::default()),
            Felt252::default(),
            Vec::default(),
            Default::default(),
            10.into(),
            block_context.invoke_tx_max_n_steps(),
            *TRANSACTION_VERSION,
        ),
        false,
        block_context.invoke_tx_max_n_steps(),
        None,
        Some(&sandbox),
    )?;

    dbg!(execution_result_native);

    Ok(())
}
