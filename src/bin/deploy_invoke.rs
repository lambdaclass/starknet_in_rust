use std::path::PathBuf;

use cairo_vm::felt::{felt_str, Felt252};
use num_traits::Zero;

use starknet_rs::{
    services::api::contract_classes::deprecated_contract_class::ContractClass,
    testing::state::StarknetState, utils::Address,
};

use lazy_static::lazy_static;

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

    static ref CONTRACT_PATH: PathBuf = PathBuf::from("starknet_programs/first_contract.json");

    static ref CONTRACT_CLASS_HASH: [u8; 32] = [5, 133, 114, 83, 104, 231, 159, 23, 87, 255, 235, 75, 170, 4, 84, 140, 49, 77, 101, 41, 147, 198, 201, 231, 38, 189, 215, 84, 231, 141, 140, 122];

    static ref CONTRACT_ADDRESS: Address = Address(1.into());

    static ref INCREASE_BALANCE_SELECTOR: Felt252 = felt_str!("1530486729947006463063166157847785599120665941190480211966374137237989315360");

    static ref GET_BALANCE_SELECTOR: Felt252 = felt_str!("1636223440827086009537493065587328807418413867743950350615962740049133672085");
}

fn main() {
    const RUNS: usize = 10000;
    let mut starknet_state = StarknetState::new(None);
    let contract_address_salt = 1.into();

    let (contract_address, _exec_info) = starknet_state
        .deploy(
            CONTRACT_CLASS.to_owned(),
            vec![],
            contract_address_salt,
            None,
            0,
        )
        .unwrap();

    // Statement **not** in blockifier.
    starknet_state
        .state
        .cache_mut()
        .nonce_initial_values_mut()
        .insert(contract_address.clone(), Felt252::zero());

    for i in 0..RUNS {
        starknet_state
            .invoke_raw(
                contract_address.clone(),
                INCREASE_BALANCE_SELECTOR.clone(),
                vec![1000.into()],
                0,
                Some(Vec::new()),
                Some(Felt252::from(i * 2)),
                None,
                0,
            )
            .unwrap();

        let tx_exec_info = starknet_state
            .invoke_raw(
                contract_address.clone(),
                GET_BALANCE_SELECTOR.clone(),
                vec![],
                0,
                Some(Vec::new()),
                Some(Felt252::from((i * 2) + 1)),
                None,
                0,
            )
            .unwrap();

        assert_eq!(
            tx_exec_info.call_info.unwrap().retdata,
            vec![((1000 * i) + 1000).into()]
        );
    }
}
