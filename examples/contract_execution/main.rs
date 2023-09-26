#![deny(warnings)]

//! A simple example of starknet-rs use.
//!
//! In [`test_contract`] we have all the interaction with the crate's API.
//! In [`main`] we use it to run a compiled contract's entrypoint and print
//! the returned data.
//!
//! It also includes some small tests that assert the data returned by
//! running some pre-compiled contracts is as expected.

use cairo_vm::felt::Felt252;
use starknet_in_rust::{
    definitions::{block_context::BlockContext, constants::TRANSACTION_VERSION},
    services::api::contract_classes::{
        compiled_class::CompiledClass, deprecated_contract_class::ContractClass,
    },
    state::{
        cached_state::CachedState, contract_class_cache::PermanentContractClassCache,
        in_memory_state_reader::InMemoryStateReader, state_api::State,
    },
    transaction::{Declare, Deploy, InvokeFunction, Transaction},
    utils::{calculate_sn_keccak, Address},
};
use std::{path::Path, sync::Arc};
use tracing_subscriber::EnvFilter;

fn main() {
    tracing::subscriber::set_global_default(
        tracing_subscriber::FmtSubscriber::builder()
            .with_env_filter(EnvFilter::from_default_env())
            .finish(),
    )
    .unwrap();

    // replace this with the path to your compiled contract
    let contract_path = "starknet_programs/fibonacci.json";

    // replace this with the name of your entrypoint
    let entry_point: &str = "fib";

    // replace this with the arguments for the entrypoint
    let calldata: Vec<Felt252> = [10.into()].to_vec();

    let retdata = test_contract(contract_path, entry_point, calldata);

    let result_strs: Vec<String> = retdata.iter().map(Felt252::to_string).collect();
    let joined_str = result_strs.join(", ");

    println!("The returned values were: {joined_str}");
}

/// This function:
///  - declares a new contract class
///  - deploys a new contract
///  - executes the given entry point in the deployed contract
fn test_contract(
    contract_path: impl AsRef<Path>,
    entry_point: &str,
    call_data: Vec<Felt252>,
) -> Vec<Felt252> {
    //* --------------------------------------------
    //*             Initialize needed variables
    //* --------------------------------------------
    let block_context = BlockContext::default();
    let chain_id = block_context.starknet_os_config().chain_id().clone();
    let sender_address = Address(1.into());
    let signature = vec![];

    //* --------------------------------------------
    //*             Initialize state
    //* --------------------------------------------
    let state_reader = Arc::new(InMemoryStateReader::default());
    let mut state = CachedState::new(
        state_reader,
        Arc::new(PermanentContractClassCache::default()),
    );

    //* --------------------------------------------
    //*          Read contract from file
    //* --------------------------------------------
    let contract_class =
        ContractClass::from_path(contract_path).expect("Could not load contract from JSON");

    //* --------------------------------------------
    //*        Declare new contract class
    //* --------------------------------------------
    let declare_tx = Declare::new(
        contract_class.clone(),
        chain_id.clone(),
        sender_address,
        0, // max fee
        0.into(),
        signature.clone(),
        0.into(), // nonce
    )
    .expect("couldn't create declare transaction");

    declare_tx
        .execute(&mut state, &block_context)
        .expect("could not declare the contract class");

    //* --------------------------------------------
    //*     Deploy new contract class instance
    //* --------------------------------------------

    let deploy = Deploy::new(
        Default::default(), // salt
        contract_class.clone(),
        vec![], // call data
        block_context.starknet_os_config().chain_id().clone(),
        TRANSACTION_VERSION.clone(),
    )
    .unwrap();

    state
        .set_contract_class(
            &deploy.contract_hash,
            &CompiledClass::Deprecated(Arc::new(contract_class)),
        )
        .unwrap();
    let contract_address = deploy.contract_address.clone();

    let tx = Transaction::Deploy(deploy);

    tx.execute(&mut state, &block_context, 0)
        .expect("could not deploy contract");

    //* --------------------------------------------
    //*        Execute contract entrypoint
    //* --------------------------------------------
    let entry_point_selector = Felt252::from_bytes_be(&calculate_sn_keccak(entry_point.as_bytes()));

    let invoke_tx = InvokeFunction::new(
        contract_address,
        entry_point_selector,
        0,
        TRANSACTION_VERSION.clone(),
        call_data,
        signature,
        chain_id,
        Some(0.into()),
    )
    .unwrap();

    let tx = Transaction::InvokeFunction(invoke_tx);
    let tx_exec_info = tx.execute(&mut state, &block_context, 0).unwrap();

    //* --------------------------------------------
    //*          Extract return values
    //* --------------------------------------------
    tx_exec_info
        .call_info
        .expect("call info should exist")
        .retdata
}

#[test]
fn test_fibonacci() {
    let retdata = test_contract(
        "starknet_programs/fibonacci.json",
        "fib",
        [1.into(), 1.into(), 10.into()].to_vec(),
    );
    assert_eq!(retdata, vec![144.into()]);
}

#[test]
fn test_factorial() {
    let retdata = test_contract(
        "starknet_programs/factorial.json",
        "factorial",
        [10.into()].to_vec(),
    );
    assert_eq!(retdata, vec![3628800.into()]);
}
