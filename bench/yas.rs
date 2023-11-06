// #![deny(clippy::pedantic)]
// #![deny(warnings)]

use cairo_vm::felt::Felt252;
use lazy_static::lazy_static;
use num_traits::{One, Zero};
use starknet_in_rust::{
    core::contract_address::compute_casm_class_hash,
    definitions::block_context::{BlockContext, StarknetChainId},
    state::{cached_state::CachedState, state_api::StateReader},
    transaction::{DeclareV2, DeployAccount},
    utils::Address,
};

lazy_static! {
    static ref OWNER_ADDRESS: Felt252 = 1234.into();
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut state = utils::default_state()?;

    // Declare ERC20, YASFactory, YASPool and YASRouter contracts.
    let erc20_class_hash = declare_erc20(&mut state)?;
    declare_yas_factory(&mut state)?;
    declare_yas_router(&mut state)?;
    declare_yas_pool(&mut state)?;

    // Deploy two ERC20 contracts.
    deploy_erc20(
        &mut state,
        &erc20_class_hash,
        "TYAS0",
        "$YAS0",
        (0x3782_dace_9d90_0000, 0),
        OWNER_ADDRESS.clone(),
    )?;
    deploy_erc20(
        &mut state,
        &erc20_class_hash,
        "TYAS1",
        "$YAS1",
        (0x3782_dace_9d90_0000, 0),
        OWNER_ADDRESS.clone(),
    )?;

    // TODO: Deploy YASFactory contract.
    // TODO: Deploy YASRouter contract.
    // TODO: Deploy YASPool contract.

    // TODO: Initialize pool (invoke).
    // TODO: Approve (invoke).
    // TODO: Swap (invoke).

    Ok(())
}

fn declare_erc20<S>(state: &mut CachedState<S>) -> Result<Felt252, Box<dyn std::error::Error>>
where
    S: StateReader,
{
    let (sierra_contract_class, casm_contract_class) = utils::load_contract("ERC20")?;
    let casm_class_hash = compute_casm_class_hash(&casm_contract_class)?;

    DeclareV2::new(
            &sierra_contract_class,
            Some(casm_contract_class),
            casm_class_hash.clone(),
            StarknetChainId::TestNet.to_felt(),
            Address(Felt252::one()),
            0,
            Felt252::one(),
            vec![],
            Felt252::one(),
        )?
        .execute(state, &BlockContext::default())?;

        println!("{:?}", casm_class_hash.to_bytes_be());
    Ok(casm_class_hash)
}

fn declare_yas_factory<S>(state: &mut CachedState<S>) -> Result<Felt252, Box<dyn std::error::Error>>
where
    S: StateReader,
{
    let (sierra_contract_class, casm_contract_class) = utils::load_contract("YASFactory")?;
    let casm_class_hash = compute_casm_class_hash(&casm_contract_class)?;

    DeclareV2::new(
        &sierra_contract_class,
        Some(casm_contract_class),
        casm_class_hash.clone(),
        StarknetChainId::TestNet.to_felt(),
        Address(Felt252::one()),
        0,
        Felt252::one(),
        vec![],
        2.into(),
    )?
    .execute(state, &BlockContext::default())?;

    Ok(casm_class_hash)
}

fn declare_yas_router<S>(state: &mut CachedState<S>) -> Result<Felt252, Box<dyn std::error::Error>>
where
    S: StateReader,
{
    let (sierra_contract_class, casm_contract_class) = utils::load_contract("YASRouter")?;
    let casm_class_hash = compute_casm_class_hash(&casm_contract_class)?;

    DeclareV2::new(
        &sierra_contract_class,
        Some(casm_contract_class),
        casm_class_hash.clone(),
        StarknetChainId::TestNet.to_felt(),
        Address(Felt252::one()),
        0,
        Felt252::one(),
        vec![],
        3.into(),
    )?
    .execute(state, &BlockContext::default())?;

    Ok(casm_class_hash)
}

fn declare_yas_pool<S>(state: &mut CachedState<S>) -> Result<Felt252, Box<dyn std::error::Error>>
where
    S: StateReader,
{
    let (sierra_contract_class, casm_contract_class) = utils::load_contract("YASPool")?;
    let casm_class_hash = compute_casm_class_hash(&casm_contract_class)?;

    DeclareV2::new(
        &sierra_contract_class,
        Some(casm_contract_class),
        casm_class_hash.clone(),
        StarknetChainId::TestNet.to_felt(),
        Address(Felt252::one()),
        0,
        Felt252::one(),
        vec![],
        4.into(),
    )?
    .execute(state, &BlockContext::default())?;

    Ok(casm_class_hash)
}

fn deploy_erc20<S>(
    state: &mut CachedState<S>,
    erc20_class_hash: &Felt252,
    name: &str,
    symbol: &str,
    initial_supply: (u128, u128),
    recipient: Felt252,
) -> Result<(), Box<dyn std::error::Error>>
where
    S: StateReader,
{
    DeployAccount::new(
        erc20_class_hash.to_be_bytes(),
        u64::MAX.into(),
        Felt252::one(),
        Felt252::zero(),
        vec![
            utils::str_to_felt252(name),
            utils::str_to_felt252(symbol),
            initial_supply.0.into(),
            initial_supply.1.into(),
            recipient,
        ],
        vec![],
        Felt252::one(),
        StarknetChainId::TestNet.to_felt(),
    )?
    .execute(state, &BlockContext::default())?;

    Ok(())
}

mod utils {
    use cairo_vm::felt::Felt252;
    use num_traits::{One, Zero};
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

    pub fn str_to_felt252(value: &str) -> Felt252 {
        assert!(value.len() < 32);
        value
            .bytes()
            .fold(Felt252::zero(), |acc, ch| (acc << 8u32) + u32::from(ch))
    }

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
