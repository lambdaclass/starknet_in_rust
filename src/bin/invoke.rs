use std::{collections::HashMap, path::PathBuf, sync::Arc};

use cairo_vm::Felt252;
use num_traits::Zero;

use starknet_in_rust::{
    definitions::{block_context::BlockContext, constants::TRANSACTION_VERSION},
    services::api::contract_classes::{
        compiled_class::CompiledClass, deprecated_contract_class::ContractClass,
    },
    state::cached_state::CachedState,
    state::in_memory_state_reader::InMemoryStateReader,
    transaction::{InvokeFunction, Transaction},
    utils::Address,
};

use lazy_static::lazy_static;

#[cfg(feature = "with_mimalloc")]
use mimalloc::MiMalloc;

#[cfg(feature = "with_mimalloc")]
#[global_allocator]
static ALLOC: MiMalloc = MiMalloc;

lazy_static! {
    // include_str! doesn't seem to work in CI
    static ref CONTRACT_CLASS: ContractClass = ContractClass::from_path(
        "starknet_programs/first_contract.json",
    ).unwrap();

    static ref CONTRACT_PATH: PathBuf = PathBuf::from("starknet_programs/first_contract.json");

    static ref CONTRACT_CLASS_HASH: [u8; 32] = [1; 32];

    static ref CONTRACT_ADDRESS: Address = Address(1.into());

    static ref INCREASE_BALANCE_SELECTOR: Felt252 = Felt252::from_dec_str("1530486729947006463063166157847785599120665941190480211966374137237989315360").unwrap();

    static ref GET_BALANCE_SELECTOR: Felt252 = Felt252::from_dec_str("1636223440827086009537493065587328807418413867743950350615962740049133672085").unwrap();
}

fn main() {
    const RUNS: usize = 10000;

    let block_context = BlockContext::default();

    let mut state = CachedState::new(
        {
            let mut state_reader = InMemoryStateReader::default();
            state_reader
                .address_to_class_hash_mut()
                .insert(CONTRACT_ADDRESS.clone(), *CONTRACT_CLASS_HASH);

            state_reader
                .address_to_nonce_mut()
                .insert(CONTRACT_ADDRESS.clone(), Felt252::zero());
            state_reader.class_hash_to_compiled_class_mut().insert(
                *CONTRACT_CLASS_HASH,
                CompiledClass::Deprecated(Arc::new(CONTRACT_CLASS.clone())),
            );

            state_reader
                .address_to_storage_mut()
                .insert((CONTRACT_ADDRESS.clone(), [0; 32]), Felt252::zero());
            Arc::new(state_reader)
        },
        HashMap::new(),
    );
    let chain_id = block_context.starknet_os_config().chain_id().clone();
    let signature = Vec::new();

    state
        .cache_mut()
        .nonce_initial_values_mut()
        .insert(CONTRACT_ADDRESS.clone(), Felt252::zero());

    for i in 0..RUNS {
        let invoke_first = InvokeFunction::new(
            CONTRACT_ADDRESS.clone(),
            INCREASE_BALANCE_SELECTOR.clone(),
            0,
            TRANSACTION_VERSION.clone(),
            vec![1000.into()],
            signature.clone(),
            chain_id.clone(),
            Some(Felt252::from(i * 2)),
        )
        .unwrap();

        let tx = Transaction::InvokeFunction(invoke_first);
        tx.execute(&mut state, &block_context, 0).unwrap();

        let invoke_second = InvokeFunction::new(
            CONTRACT_ADDRESS.clone(),
            GET_BALANCE_SELECTOR.clone(),
            0,
            TRANSACTION_VERSION.clone(),
            vec![],
            signature.clone(),
            chain_id.clone(),
            Some(Felt252::from((i * 2) + 1)),
        )
        .unwrap();

        let tx = Transaction::InvokeFunction(invoke_second);
        let tx_exec_info = tx.execute(&mut state, &block_context, 0).unwrap();

        assert_eq!(
            tx_exec_info.call_info.unwrap().retdata,
            vec![((1000 * i) + 1000).into()]
        );
    }
}
