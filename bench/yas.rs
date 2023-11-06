use cairo_vm::felt::Felt252;
use num_traits::One;
use starknet_in_rust::{
    core::contract_address::compute_casm_class_hash,
    definitions::block_context::{BlockContext, StarknetChainId},
    state::{cached_state::CachedState, state_api::StateReader},
    transaction::DeclareV2,
    utils::Address,
};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut state = utils::default_state()?;

    // // Declare ERC20, YASFactory, YASPool and YASRouter contracts.
    declare_erc20(&mut state)?;
    // declare_yas_factory(&mut state);
    // // declare_yas_pool(&mut state);
    // // declare_yas_router(&mut state);

    // // TODO: Deploy ERC20 contract.
    // // TODO: Deploy YASFactory contract.
    // // TODO: Deploy YASRouter contract.
    // // TODO: Deploy YASPool contract.

    // // TODO: Initialize pool (invoke).
    // // TODO: Approve (invoke).
    // // TODO: Swap (invoke).

    Ok(())
}

fn declare_erc20<S>(state: &mut CachedState<S>) -> Result<(), Box<dyn std::error::Error>>
where
    S: StateReader,
{
    let (sierra_contract_class, casm_contract_class) = utils::load_contract("ERC20")?;
    let casm_class_hash = compute_casm_class_hash(&casm_contract_class)?;

    DeclareV2::new(
        &sierra_contract_class,
        Some(casm_contract_class),
        casm_class_hash,
        StarknetChainId::TestNet.to_felt(),
        Address(Felt252::one()),
        0,
        Felt252::one(),
        vec![],
        Felt252::one(),
    )?
    .execute(state, &BlockContext::default())?;

    Ok(())
}

// fn declare_yas_factory<S>(state: &mut CachedState<S>)
// where
//     S: StateReader,
// {
//     Declare::new(
//         ContractClass::from_path("bench/yas/yas_core_YASFactory.sierra.json").unwrap(),
//         StarknetChainId::TestNet.to_felt(),
//         Address(Felt252::one()),
//         0,
//         1.into(),
//         vec![],
//         Felt252::zero(),
//     )
//     .unwrap()
//     .apply(state, &BlockContext::default())
//     .unwrap();
// }

mod utils {
    use cairo_vm::felt::Felt252;
    use num_traits::One;
    use starknet_in_rust::{
        core::contract_address::compute_deprecated_class_hash,
        services::api::contract_classes::{
            compiled_class::CompiledClass, deprecated_contract_class::ContractClass,
        },
        state::{cached_state::CachedState, in_memory_state_reader::InMemoryStateReader},
        utils::Address,
        CasmContractClass, ContractClass as SierraContractClass,
    };
    use std::{collections::HashMap, fs, path::Path, sync::Arc};

    const BASE_DIR: &str = "bench/yas/";

    pub fn default_state() -> Result<CachedState<InMemoryStateReader>, Box<dyn std::error::Error>> {
        let contract_class =
            ContractClass::from_path("starknet_programs/account_without_validation.json")?;
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

        Ok(CachedState::new(
            Arc::new(state_reader),
            HashMap::from([(
                contract_class_hash,
                CompiledClass::Deprecated(Arc::new(contract_class)),
            )]),
        ))
    }

    pub fn load_contract(
        name: &str,
    ) -> Result<(SierraContractClass, CasmContractClass), Box<dyn std::error::Error>> {
        let sierra_contract_class = serde_json::from_str::<SierraContractClass>(
            &fs::read_to_string(Path::new(BASE_DIR).join(name).with_extension("sierra.json"))?,
        )?;
        let casm_contract_class = serde_json::from_str::<CasmContractClass>(&fs::read_to_string(
            Path::new(BASE_DIR).join(name).with_extension("json"),
        )?)?;

        Ok((sierra_contract_class, casm_contract_class))
    }
}
