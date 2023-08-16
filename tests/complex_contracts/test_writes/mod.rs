use std::sync::Arc;

use cairo_vm::felt::Felt252;
use starknet_in_rust::{definitions::block_context::{BlockContext, StarknetChainId}, state::{in_memory_state_reader::InMemoryStateReader, cached_state::CachedState}, transaction::InvokeFunction, utils::calculate_sn_keccak};

use super::utils::deploy;

#[ignore]
#[test]
fn test_invoke_compare_writes() {
    let block_context = BlockContext::default();
    let mut state = CachedState::new(
        Arc::new(InMemoryStateReader::default()),
        Some(Default::default()),
        None,
    );

    let contract_path = "starknet_programs/cairo1/test_writes.casm";
    // Deploy contract
    let (contract_address, _class_hash) = deploy(
        &mut state,
        contract_path,
        &[],
        &block_context,
        None,
    )
    .unwrap();

    let calldata = vec![42.into()];
    let invoke = InvokeFunction::new(
        contract_address,
        Felt252::from_bytes_be(&calculate_sn_keccak(b"write_foo")),
        50000000,
        1.into(),
        calldata,
        vec![],
        StarknetChainId::TestNet.to_felt(),
        Some(0.into()),
    )
    .unwrap();

    let _result = invoke.execute(&mut state, &block_context, 99999999999).unwrap();
}
