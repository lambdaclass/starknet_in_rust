use cairo_vm::felt::Felt252;
use num_traits::{One, Zero};
use starknet_in_rust::{
    core::contract_address::compute_deprecated_class_hash,
    definitions::block_context::{BlockContext, StarknetChainId},
    services::api::contract_classes::{
        compiled_class::CompiledClass, deprecated_contract_class::ContractClass,
    },
    state::{
        cached_state::CachedState, in_memory_state_reader::InMemoryStateReader,
        state_api::StateReader,
    },
    transaction::Declare,
    utils::Address,
};
use std::{collections::HashMap, sync::Arc};

fn main() {
    let contract_class =
        ContractClass::from_path("starknet_programs/account_without_validation.json").unwrap();
    let contract_class_hash = compute_deprecated_class_hash(&contract_class)
        .unwrap()
        .to_be_bytes();

    let mut state_reader = InMemoryStateReader::default();
    state_reader
        .address_to_class_hash_mut()
        .insert(Address(Felt252::one()), contract_class_hash);
    state_reader
        .address_to_nonce_mut()
        .insert(Address(Felt252::one()), Felt252::one());

    let mut state = CachedState::new(
        Arc::new(state_reader),
        HashMap::from([(
            contract_class_hash,
            CompiledClass::Deprecated(Arc::new(contract_class)),
        )]),
    );

    // Declare ERC20, YASFactory, YASPool and YASRouter contracts.
    declare_erc20(&mut state);
    // declare_yas_factory(&mut state);
    // declare_yas_pool(&mut state);
    // declare_yas_router(&mut state);

    // TODO: Deploy ERC20 contract.
    // TODO: Deploy YASFactory contract.
    // TODO: Deploy YASRouter contract.
    // TODO: Deploy YASPool contract.

    // TODO: Initialize pool (invoke).
    // TODO: Approve (invoke).
    // TODO: Swap (invoke).
}

fn declare_erc20<S>(state: &mut CachedState<S>)
where
    S: StateReader,
{
    let declare_tx = Declare::new(
        ContractClass::from_path("starknet_programs/ERC20.json").unwrap(),
        StarknetChainId::TestNet.to_felt(),
        Address(Felt252::one()),
        0,
        1.into(),
        vec![],
        Felt252::zero(),
    )
    .unwrap();

    declare_tx.apply(state, &BlockContext::default()).unwrap();
}
