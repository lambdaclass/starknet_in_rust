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
    services::api::contract_classes::deprecated_contract_class::ContractClass,
    testing::state::StarknetState,
    utils::{calculate_sn_keccak, Address},
};
use std::path::Path;

fn main() {
    // replace this with the path to your compiled contract
    let contract_path = "starknet_programs/factorial.json";

    // replace this with the name of your entrypoint
    let entry_point: &str = "factorial";

    // replace this with the arguments for the entrypoint
    let calldata: Vec<Felt252> = [1.into(), 1.into(), 10.into()].to_vec();

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
    calldata: Vec<Felt252>,
) -> Vec<Felt252> {
    //* --------------------------------------------
    //*             Initialize state
    //* --------------------------------------------
    let mut state = StarknetState::new(None);

    //* --------------------------------------------
    //*          Read contract from file
    //* --------------------------------------------
    let contract_class =
        ContractClass::from_path(contract_path).expect("Could not load contract from JSON");

    //* --------------------------------------------
    //*        Declare new contract class
    //* --------------------------------------------
    state
        .declare(contract_class.clone(), None)
        .expect("Could not declare the contract class");

    //* --------------------------------------------
    //*     Deploy new contract class instance
    //* --------------------------------------------
    let (contract_address, _) = state
        .deploy(contract_class, vec![], Default::default(), None, 0)
        .expect("Could not deploy contract");

    //* --------------------------------------------
    //*        Execute contract entrypoint
    //* --------------------------------------------
    let entry_point_selector = Felt252::from_bytes_be(&calculate_sn_keccak(entry_point.as_bytes()));

    let caller_address = Address::default();

    let callinfo = state
        .execute_entry_point_raw(
            contract_address,
            entry_point_selector,
            calldata,
            caller_address,
        )
        .expect("Could not execute entry point");

    //* --------------------------------------------
    //*          Extract return values
    //* --------------------------------------------
    callinfo.retdata
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
