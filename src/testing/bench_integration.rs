use std::{collections::HashMap, path::PathBuf};

use felt::{felt_str, Felt};
use num_traits::Zero;

use crate::{
    business_logic::{
        fact_state::in_memory_state_reader::InMemoryStateReader, state::cached_state::CachedState,
    },
    definitions::general_config::StarknetGeneralConfig,
    services::api::contract_class::ContractClass,
    testing::starknet_state::StarknetState,
    utils::Address,
};

use lazy_static::lazy_static;

lazy_static! {
    // include_str! doesn't seem to work in CI
    static ref CONTRACT_CLASS: ContractClass = ContractClass::try_from(PathBuf::from(
        "starknet_programs/first_contract.json",
    )).unwrap();

    static ref CONTRACT_PATH: PathBuf = PathBuf::from("starknet_programs/first_contract.json");

    static ref CONTRACT_CLASS_HASH: [u8; 32] = [0; 32];

    static ref CONTRACT_ADDRESS: Address = Address(1.into());

    static ref INCREASE_BALANCE_SELECTOR: Felt = felt_str!("1530486729947006463063166157847785599120665941190480211966374137237989315360");

    static ref GET_BALANCE_SELECTOR: Felt = felt_str!("1636223440827086009537493065587328807418413867743950350615962740049133672085");
}

#[test]
fn test_invoke() {
    const RUNS: usize = 10000;
    let cached_state = create_initial_state().unwrap();

    let mut starknet_state = StarknetState {
        state: cached_state,
        ..Default::default()
    };

    starknet_state
        .state
        .cache_mut()
        .nonce_initial_values_mut()
        .insert(CONTRACT_ADDRESS.clone(), Felt::zero());

    for i in (0..RUNS * 2).step_by(2) {
        starknet_state
            .invoke_raw(
                CONTRACT_ADDRESS.clone(),
                INCREASE_BALANCE_SELECTOR.clone(),
                vec![1000.into()],
                0,
                Some(Vec::new()),
                Some(Felt::from(i)),
            )
            .unwrap();

        starknet_state
            .invoke_raw(
                CONTRACT_ADDRESS.clone(),
                GET_BALANCE_SELECTOR.clone(),
                vec![],
                0,
                Some(Vec::new()),
                Some(Felt::from(i + 1)),
            )
            .unwrap();
    }
}

fn create_initial_state() -> Result<CachedState<InMemoryStateReader>, Box<dyn std::error::Error>> {
    let cached_state = CachedState::new(
        {
            let mut state_reader = InMemoryStateReader::default();
            state_reader
                .address_to_class_hash_mut()
                .insert(CONTRACT_ADDRESS.clone(), CONTRACT_CLASS_HASH.clone());

            state_reader
                .address_to_nonce_mut()
                .insert(CONTRACT_ADDRESS.clone(), Felt::zero());
            state_reader
                .class_hash_to_contract_class_mut()
                .insert(CONTRACT_CLASS_HASH.clone(), CONTRACT_CLASS.clone());

            state_reader.address_to_storage_mut().insert(
                (CONTRACT_ADDRESS.clone(), STORAGE_KEY.clone()),
                Felt::zero(),
            );
            state_reader
        },
        Some(HashMap::new()),
    );

    Ok(cached_state)
}
