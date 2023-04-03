#![deny(warnings)]

use felt::{felt_str, Felt};
use lazy_static::lazy_static;
use num_traits::Zero;
use starknet_rs::{
    business_logic::{
        fact_state::in_memory_state_reader::InMemoryStateReader,
        state::{cached_state::CachedState, state_api::State},
        transaction::objects::{
            internal_deploy::InternalDeploy,
            // internal_deploy_account::InternalDeployAccount,
            internal_invoke_function::InternalInvokeFunction,
        },
    },
    // core::contract_address::starknet_contract_address::compute_class_hash,
    definitions::general_config::StarknetChainId,
    // public::abi::VALIDATE_ENTRY_POINT_SELECTOR,
    services::api::contract_class::ContractClass,
    utils::Address,
};
use std::{hint::black_box, path::PathBuf};

lazy_static! {
    // include_str! doesn't seem to work in CI
    static ref CONTRACT_CLASS: ContractClass = ContractClass::try_from(PathBuf::from(
        "starknet_programs/first_contract.json",
    ))
    .unwrap();
    // static ref CLASS_HASH: [u8; 32] = felt_to_hash(&compute_class_hash(
    //     &CONTRACT_CLASS
    // ).unwrap());
    static ref CLASS_HASH: [u8; 32] = [5, 133, 114, 83, 104, 231, 159, 23, 87, 255, 235, 75, 170, 4, 84, 140, 49, 77, 101, 41, 147, 198, 201, 231, 38, 189, 215, 84, 231, 141, 140, 122];
    static ref CONTRACT_ADDRESS: Address = Address(felt_str!(
        "2738486479303299496454183918921854338184575157042818123638928295804546084002"
    ));
    static ref SIGNATURE: Vec<Felt> = vec![
        felt_str!("3233776396904427614006684968846859029149676045084089832563834729503047027074"),
        felt_str!("707039245213420890976709143988743108543645298941971188668773816813012281203"),
    ];

    // increase_balance() selector
    static ref INCREASE_BALANCE_SELECTOR: Felt =
        felt_str!("1530486729947006463063166157847785599120665941190480211966374137237989315360");
    // get_balance() selector
    static ref GET_BALANCE_SELECTOR: Felt =
        felt_str!("1636223440827086009537493065587328807418413867743950350615962740049133672085");
}

// This function just executes the given function. This adds a stack level
// to the flamegraph with the label "scope".
#[inline(never)]
fn scope<T>(f: impl FnOnce() -> T) -> T {
    f()
}

// We don't use the cargo test harness because it uses
// FnOnce calls for each test, that are merged in the flamegraph.
fn main() {
    // deploy_account();
    // declare();
    // deploy();
    invoke();

    // The black_box ensures there's no tail-call optimization.
    // If not, the flamegraph ends up less nice.
    black_box(());
}

// #[inline(never)]
// fn deploy_account() {
//     const RUNS: usize = 500;

//     let state_reader = InMemoryStateReader::default();
//     let mut state = CachedState::new(state_reader, Some(Default::default()));

//     state
//         .set_contract_class(&CLASS_HASH, &CONTRACT_CLASS)
//         .unwrap();

//     let config = &Default::default();

//     for _ in 0..RUNS {
//         let mut state_copy = state.clone();
//         let salt = Address(felt_str!(
//             "2669425616857739096022668060305620640217901643963991674344872184515580705509"
//         ));
//         let class_hash = *CLASS_HASH;
//         let signature = SIGNATURE.clone();
//         scope(|| {
//             // new consumes more execution time than raw struct instantiation
//             let internal_deploy_account = InternalDeployAccount::new(
//                 class_hash,
//                 0,
//                 0,
//                 Felt::zero(),
//                 vec![],
//                 signature,
//                 salt,
//                 StarknetChainId::TestNet,
//             )
//             .unwrap();
//             internal_deploy_account.execute(&mut state_copy, config)
//         })
//         .unwrap();
//     }
// }

// #[inline(never)]
// fn declare() {
//     const RUNS: usize = 5;

//     let state_reader = InMemoryStateReader::default();
//     let state = CachedState::new(state_reader, Some(Default::default()));

//     let config = &Default::default();

//     for _ in 0..RUNS {
//         let mut cloned_state = state.clone();
//         let class = CONTRACT_CLASS.clone();
//         let address = CONTRACT_ADDRESS.clone();
//         scope(|| {
//             // new consumes more execution time than raw struct instantiation
//             let declare_tx = InternalDeclare::new(
//                 class,
//                 StarknetChainId::TestNet.to_felt(),
//                 address,
//                 0,
//                 0,
//                 vec![],
//                 Felt::zero(),
//             )
//             .expect("couldn't create transaction");

//             declare_tx.execute(&mut cloned_state, config)
//         })
//         .unwrap();
//     }
// }

// #[inline(never)]
// fn deploy() {
//     const RUNS: usize = 8;

//     let state_reader = InMemoryStateReader::default();
//     let mut state = CachedState::new(state_reader, Some(Default::default()));

//     state
//         .set_contract_class(&CLASS_HASH, &CONTRACT_CLASS)
//         .unwrap();

//     let config = &Default::default();

//     for _ in 0..RUNS {
//         let mut state_copy = state.clone();
//         let salt = Address(felt_str!(
//             "2669425616857739096022668060305620640217901643963991674344872184515580705509"
//         ));
//         let class = CONTRACT_CLASS.clone();
//         scope(|| {
//             // new consumes more execution time than raw struct instantiation
//             let internal_deploy =
//                 InternalDeploy::new(salt, class, vec![], StarknetChainId::TestNet.to_felt(), 0)
//                     .unwrap();
//             internal_deploy.execute(&mut state_copy, config)
//         })
//         .unwrap();
//     }
// }

#[inline(never)]
fn invoke() {
    const RUNS: usize = 10000;
    let mut state_reader = InMemoryStateReader::default();
    state_reader
        .address_to_nonce_mut()
        .insert(CONTRACT_ADDRESS.clone(), Felt::zero());
    let mut state = CachedState::new(state_reader, Some(Default::default()));

    state
        .set_contract_class(&CLASS_HASH, &CONTRACT_CLASS)
        .unwrap();

    let config = &Default::default();

    let salt = Address(felt_str!(
        "2669425616857739096022668060305620640217901643963991674344872184515580705509"
    ));
    let class = CONTRACT_CLASS.clone();

    InternalDeploy::new(salt, class, vec![], StarknetChainId::TestNet.to_felt(), 0)
        .unwrap()
        .execute(&mut state, config)
        .unwrap();

    //let state_copy = state.clone();
    let address = CONTRACT_ADDRESS.clone();
    // let selector = INCREASE_BALANCE_SELECTOR.clone();
    let signature = SIGNATURE.clone();
    let calldata = vec![Felt::from(2)];

    let mut state_copy = state.clone();
    for i in (0..(RUNS * 2)).step_by(2) {
        // let mut state_copy = state_copy.clone();
        let address = address.clone();
        let selector = INCREASE_BALANCE_SELECTOR.clone();
        let calldata = calldata.clone();
        let signature = signature.clone();
        scope(|| {
            // increase balance
            // new consumes more execution time than raw struct instantiation
            InternalInvokeFunction::new(
                address.clone(),
                selector,
                0,
                calldata,
                signature.clone(),
                StarknetChainId::TestNet.to_felt(),
                Some(Felt::from(i)),
            )
            .unwrap()
            .execute(&mut state_copy, config)
            .unwrap();

            InternalInvokeFunction::new(
                address,
                GET_BALANCE_SELECTOR.clone(),
                0,
                vec![],
                signature,
                StarknetChainId::TestNet.to_felt(),
                Some(Felt::from(i + 1)),
            )
            .unwrap()
            .execute(&mut state_copy, config)
            .unwrap();
        });
    }
}
