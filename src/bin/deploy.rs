use std::path::PathBuf;

use lazy_static::lazy_static;
use starknet_in_rust::{
    services::api::contract_classes::deprecated_contract_class::ContractClass,
    testing::state::StarknetState,
};

#[cfg(feature = "with_mimalloc")]
use mimalloc::MiMalloc;

#[cfg(feature = "with_mimalloc")]
#[global_allocator]
static ALLOC: MiMalloc = MiMalloc;

lazy_static! {
    // include_str! doesn't seem to work in CI
    static ref CONTRACT_CLASS: ContractClass = ContractClass::try_from(PathBuf::from(
        "starknet_programs/first_contract.json",
    )).unwrap();
}

fn main() {
    const RUNS: usize = 100;
    let mut starknet_state = StarknetState::new(None);

    for n in 0..RUNS {
        let contract_address_salt = n.into();

        starknet_state
            .deploy(
                CONTRACT_CLASS.clone(),
                vec![],
                contract_address_salt,
                None,
                0,
            )
            .unwrap();
    }
}
