#![deny(warnings)]

use felt::{felt_str, Felt252};
use num_traits::Zero;
use starknet_rs::{
    business_logic::{
        execution::objects::{CallInfo, CallType, TransactionExecutionInfo},
        fact_state::in_memory_state_reader::InMemoryStateReader,
        state::{cached_state::CachedState, state_api::State},
        transaction::objects::internal_deploy_account::InternalDeployAccount,
    },
    core::contract_address::starknet_contract_address::compute_class_hash,
    definitions::{
        constants::CONSTRUCTOR_ENTRY_POINT_SELECTOR, general_config::StarknetChainId,
        transaction_type::TransactionType,
    },
    services::api::contract_class::{ContractClass, EntryPointType},
    utils::{felt_to_hash, Address},
};
use std::path::PathBuf;

#[test]
fn internal_deploy_account() {
    let state_reader = InMemoryStateReader::default();
    let mut state = CachedState::new(state_reader, None);

    state.set_contract_classes(Default::default()).unwrap();

    let contract_class = ContractClass::try_from(PathBuf::from(
        "starknet_programs/account_without_validation.json",
    ))
    .unwrap();

    let class_hash = felt_to_hash(&compute_class_hash(&contract_class).unwrap());

    state
        .set_contract_class(&class_hash, &contract_class)
        .unwrap();

    let internal_deploy_account = InternalDeployAccount::new(
        class_hash,
        0,
        0,
        Felt252::zero(),
        vec![],
        vec![
            felt_str!(
                "3233776396904427614006684968846859029149676045084089832563834729503047027074"
            ),
            felt_str!(
                "707039245213420890976709143988743108543645298941971188668773816813012281203"
            ),
        ],
        Address(felt_str!(
            "2669425616857739096022668060305620640217901643963991674344872184515580705509"
        )),
        StarknetChainId::TestNet,
    )
    .unwrap();

    let tx_info = internal_deploy_account
        .execute(&mut state, &Default::default())
        .unwrap();

    assert_eq!(
        tx_info,
        TransactionExecutionInfo::new(
            None,
            Some(CallInfo {
                call_type: Some(CallType::Call),
                contract_address: Address(felt_str!(
                    "3577223136242220508961486249701638158054969090851914040041358274796489907314"
                )),
                class_hash: Some(class_hash),
                entry_point_selector: Some(CONSTRUCTOR_ENTRY_POINT_SELECTOR.clone()),
                entry_point_type: Some(EntryPointType::Constructor),
                ..Default::default()
            }),
            None,
            0,
            [
                ("pedersen_builtin", 23),
                ("range_check_builtin", 74),
                ("l1_gas_usage", 1224)
            ]
            .into_iter()
            .map(|(k, v)| (k.to_string(), v))
            .collect(),
            Some(TransactionType::DeployAccount),
        ),
    );
}
