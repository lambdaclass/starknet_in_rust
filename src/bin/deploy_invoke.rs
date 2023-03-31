use std::path::PathBuf;

use felt::{felt_str, Felt};
use num_traits::Zero;

use starknet_rs::{
    services::api::contract_class::ContractClass, testing::starknet_state::StarknetState,
    utils::Address,
};

use lazy_static::lazy_static;

lazy_static! {
    // include_str! doesn't seem to work in CI
    static ref CONTRACT_CLASS: ContractClass = ContractClass::try_from(PathBuf::from(
        "starknet_programs/first_contract.json",
    )).unwrap();

    static ref CONTRACT_PATH: PathBuf = PathBuf::from("starknet_programs/first_contract.json");

    static ref CONTRACT_CLASS_HASH: [u8; 32] = [5, 133, 114, 83, 104, 231, 159, 23, 87, 255, 235, 75, 170, 4, 84, 140, 49, 77, 101, 41, 147, 198, 201, 231, 38, 189, 215, 84, 231, 141, 140, 122];

    static ref CONTRACT_ADDRESS: Address = Address(1.into());

    static ref INCREASE_BALANCE_SELECTOR: Felt = felt_str!("1530486729947006463063166157847785599120665941190480211966374137237989315360");

    static ref GET_BALANCE_SELECTOR: Felt = felt_str!("1636223440827086009537493065587328807418413867743950350615962740049133672085");
}

fn main() {
    const RUNS: usize = 10000;
    let mut starknet_state = StarknetState::new(None);
    let contract_address_salt = Address(1.into());

    let (contract_address, _exec_info) = starknet_state
        .deploy(CONTRACT_CLASS.to_owned(), vec![], contract_address_salt)
        .unwrap();

    // Statement **not** in blockifier.
    starknet_state
        .state
        .cache_mut()
        .nonce_initial_values_mut()
        .insert(contract_address.clone(), Felt::zero());

    for i in 0..RUNS {
        starknet_state
            .invoke_raw(
                contract_address.clone(),
                INCREASE_BALANCE_SELECTOR.clone(),
                vec![1000.into()],
                0,
                Some(Vec::new()),
                Some(Felt::from(i * 2)),
            )
            .unwrap();

        starknet_state
            .invoke_raw(
                contract_address.clone(),
                GET_BALANCE_SELECTOR.clone(),
                vec![],
                0,
                Some(Vec::new()),
                Some(Felt::from((i * 2) + 1)),
            )
            .unwrap();
    }
}
