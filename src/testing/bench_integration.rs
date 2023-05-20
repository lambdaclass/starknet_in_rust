use std::{collections::HashMap, path::PathBuf};

use felt::{felt_str, Felt};
use num_traits::Zero;

use crate::{
    business_logic::{
        fact_state::in_memory_state_reader::InMemoryStateReader, state::cached_state::CachedState,
    },
    services::api::contract_classes::deprecated_contract_class::ContractClass,
    utils::Address, testing::starknet_state::StarknetState,
};

use lazy_static::lazy_static;

lazy_static! {
    // include_str! doesn't seem to work in CI
    static ref CONTRACT_CLASS: ContractClass = ContractClass::try_from(PathBuf::from(
        "starknet_programs/first_contract.json",
    )).unwrap();

    static ref CONTRACT_PATH: PathBuf = PathBuf::from("starknet_programs/first_contract.json");

    static ref CONTRACT_CLASS_HASH: [u8; 32] = [1; 32];

    static ref CONTRACT_ADDRESS: Address = Address(1.into());

    static ref INCREASE_BALANCE_SELECTOR: Felt = felt_str!("1530486729947006463063166157847785599120665941190480211966374137237989315360");

    static ref GET_BALANCE_SELECTOR: Felt = felt_str!("1636223440827086009537493065587328807418413867743950350615962740049133672085");
}

#[test]
fn main() {
    const RUNS: usize = 1000;
    let cached_state = create_initial_state();

    let mut starknet_state = StarknetState {
        state: cached_state,
        ..Default::default()
    };

    starknet_state
        .state
        .cache_mut()
        .nonce_initial_values_mut()
        .insert(CONTRACT_ADDRESS.clone(), Felt::zero());

    for i in 0..RUNS {
        starknet_state
            .invoke_raw(
                CONTRACT_ADDRESS.clone(),
                INCREASE_BALANCE_SELECTOR.clone(),
                vec![1000.into()],
                0,
                Some(Vec::new()),
                Some(Felt::from(i*2)),
            )
            .unwrap();

        let tx_exec_info = starknet_state
            .invoke_raw(
                CONTRACT_ADDRESS.clone(),
                GET_BALANCE_SELECTOR.clone(),
                vec![],
                0,
                Some(Vec::new()),
                Some(Felt::from((i*2) + 1)),
            )
            .unwrap();

            assert_eq!(
                tx_exec_info.call_info.unwrap().retdata,
                vec![((1000 * i) + 1000).into()]
            );
    }
}

fn create_initial_state() -> CachedState<InMemoryStateReader> {
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

            state_reader
                .address_to_storage_mut()
                .insert((CONTRACT_ADDRESS.clone(), [0; 32]), Felt::zero());
            state_reader
        },
        Some(HashMap::new()),
    );

    cached_state
}
