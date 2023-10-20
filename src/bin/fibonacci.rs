use std::{collections::HashMap, path::PathBuf, sync::Arc};

use cairo_vm::felt::{felt_str, Felt252};
use num_traits::Zero;

use lazy_static::lazy_static;
use starknet_in_rust::{
    definitions::{block_context::BlockContext, constants::TRANSACTION_VERSION},
    execution::{
        execution_entry_point::ExecutionEntryPoint, CallType, TransactionExecutionContext,
    },
    services::api::contract_classes::{
        compiled_class::CompiledClass, deprecated_contract_class::ContractClass,
    },
    state::cached_state::CachedState,
    state::{in_memory_state_reader::InMemoryStateReader, ExecutionResourcesManager},
    utils::{Address, ClassHash},
    EntryPointType,
};

#[cfg(feature = "with_mimalloc")]
use mimalloc::MiMalloc;

#[cfg(feature = "with_mimalloc")]
#[global_allocator]
static ALLOC: MiMalloc = MiMalloc;

lazy_static! {
    // include_str! doesn't seem to work in CI
    static ref CONTRACT_CLASS: ContractClass = ContractClass::from_path(
        "starknet_programs/fibonacci.json",
    ).unwrap();

    static ref CONTRACT_PATH: PathBuf = PathBuf::from("starknet_programs/fibonacci.json");

    static ref CONTRACT_CLASS_HASH_BYTES: [u8; 32] = [1; 32];

    static ref CONTRACT_ADDRESS: Address = Address(1.into());

    static ref FIB_SELECTOR: Felt252 = felt_str!("485685360977693822178494178685050472186234432883326654755380582597179924681");

    static ref EXPECTED_RES: Felt252 = felt_str!("222450955505511890955301767713383614666194461405743219770606958667979327682");
}

fn main() {
    const RUNS: usize = 1000;

    let contract_class = ContractClass::from_path(&*CONTRACT_PATH).unwrap();
    let entry_points_by_type = contract_class.entry_points_by_type().clone();

    let fib_entrypoint_selector = entry_points_by_type
        .get(&EntryPointType::External)
        .unwrap()
        .get(0)
        .unwrap()
        .selector()
        .clone();

    //* --------------------------------------------
    //*    Create state reader with class hash data
    //* --------------------------------------------

    let mut contract_class_cache = HashMap::new();

    //  ------------ contract data --------------------

    let contract_address = CONTRACT_ADDRESS.clone();
    let class_hash = ClassHash::from(*CONTRACT_CLASS_HASH_BYTES);
    let nonce = Felt252::zero();

    contract_class_cache.insert(
        class_hash,
        CompiledClass::Deprecated(Arc::new(contract_class)),
    );
    let mut state_reader = InMemoryStateReader::default();
    state_reader
        .address_to_class_hash_mut()
        .insert(contract_address.clone(), class_hash);
    state_reader
        .address_to_nonce_mut()
        .insert(contract_address.clone(), nonce);

    //* ---------------------------------------
    //*    Create state with previous data
    //* ---------------------------------------

    let mut state = CachedState::new(Arc::new(state_reader), contract_class_cache);

    //* ------------------------------------
    //*    Create execution entry point
    //* ------------------------------------

    let calldata = [1.into(), 1.into(), 1000.into()].to_vec();
    let caller_address = Address(0000.into());
    let entry_point_type = EntryPointType::External;

    for nonce in 0..RUNS {
        let exec_entry_point = ExecutionEntryPoint::new(
            contract_address.clone(),
            calldata.clone(),
            fib_entrypoint_selector.clone(),
            caller_address.clone(),
            entry_point_type,
            Some(CallType::Delegate),
            Some(class_hash),
            0,
        );

        //* --------------------
        //*   Execute contract
        //* ---------------------
        let block_context = BlockContext::default();
        let mut tx_execution_context = TransactionExecutionContext::new(
            Address(0.into()),
            Felt252::zero(),
            Vec::new(),
            0,
            nonce.into(),
            block_context.invoke_tx_max_n_steps(),
            TRANSACTION_VERSION.clone(),
        );
        let mut resources_manager = ExecutionResourcesManager::default();

        let tx_exec_result = exec_entry_point
            .execute(
                &mut state,
                &block_context,
                &mut resources_manager,
                &mut tx_execution_context,
                false,
                block_context.invoke_tx_max_n_steps(),
            )
            .unwrap();

        assert_eq!(
            tx_exec_result.call_info.unwrap().retdata,
            vec![EXPECTED_RES.clone()]
        );
    }
}
