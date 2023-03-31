use std::path::PathBuf;

use lazy_static::lazy_static;
use starknet_rs::{
    services::api::contract_class::ContractClass, testing::starknet_state::StarknetState,
    utils::Address,
};

lazy_static! {
    // include_str! doesn't seem to work in CI
    static ref CONTRACT_CLASS: ContractClass = ContractClass::try_from(PathBuf::from(
        "starknet_programs/first_contract.json",
    )).unwrap();
}

fn main() {
    const RUNS: usize = 10;
    let mut starknet_state = StarknetState::new(None);

    for n in 0..RUNS {
        let contract_address_salt = Address(n.into());

        starknet_state
            .deploy(CONTRACT_CLASS.clone(), vec![], contract_address_salt)
            .unwrap();
    }
}
