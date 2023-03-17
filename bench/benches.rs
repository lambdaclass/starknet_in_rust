#![deny(warnings)]

use felt::{felt_str, Felt};
use num_traits::Zero;
use starknet_rs::{
    business_logic::{
        execution::objects::{CallInfo, CallType, TransactionExecutionInfo},
        fact_state::in_memory_state_reader::InMemoryStateReader,
        state::{cached_state::CachedState, state_api::State},
        transaction::objects::internal_deploy_account::InternalDeployAccount,
    },
    definitions::{
        constants::CONSTRUCTOR_ENTRY_POINT_SELECTOR, general_config::StarknetChainId,
        transaction_type::TransactionType,
    },
    services::api::contract_class::{ContractClass, EntryPointType},
    utils::{felt_to_hash, Address},
};

#[test]
fn internal_deploy_account() {
    const RUNS: usize = 500;

    let state_reader = InMemoryStateReader::new(Default::default(), Default::default());
    let mut state = CachedState::new(state_reader, None);

    state.set_contract_classes(Default::default()).unwrap();

    let class_hash = felt_to_hash(&felt_str!(
        "3146761231686369291210245479075933162526514193311043598334639064078158562617"
    ));
    let contract_class = ContractClass::try_from(include_str!(
        "../starknet_programs/account_without_validation.json",
    ))
    .unwrap();

    state
        .set_contract_class(&class_hash, &contract_class)
        .unwrap();

    let expected = TransactionExecutionInfo::new(
        None,
        Some(CallInfo {
            call_type: Some(CallType::Call),
            contract_address: Address(felt_str!("1351769743764599227746416364615306404319526869558988948822078481252102329345")),
            class_hash: Some(*b"\x06\xf5\x00\xf5'5]\xfd\xb8\t<\x7f\xe4nos\xc9j\x86s\x92\xb4\x9f\xa4\x15zuu8\x92\x859"),
            entry_point_selector: Some(CONSTRUCTOR_ENTRY_POINT_SELECTOR.clone()),
            entry_point_type: Some(EntryPointType::Constructor),
            ..Default::default()
        }),
        None,
        0,
        [("l1_gas_usage", 1224)]
            .into_iter()
            .map(|(k, v)| (k.to_string(), v))
            .collect(),
        Some(TransactionType::DeployAccount),
    );
    let config = &Default::default();

    for _ in 0..RUNS {
        let mut state_copy = state.clone();
        let signature = vec![
            felt_str!(
                "3233776396904427614006684968846859029149676045084089832563834729503047027074"
            ),
            felt_str!(
                "707039245213420890976709143988743108543645298941971188668773816813012281203"
            ),
        ];
        let salt = Address(felt_str!(
            "2669425616857739096022668060305620640217901643963991674344872184515580705509"
        ));
        let got = scope(|| {
            let internal_deploy_account = InternalDeployAccount::new(
                class_hash,
                0,
                0,
                Felt::zero(),
                vec![],
                signature,
                salt,
                StarknetChainId::TestNet,
            )
            .unwrap();
            internal_deploy_account
                .execute(&mut state_copy, config)
                .unwrap()
        });
        assert_eq!(got, expected);
    }
}

#[inline(never)]
fn scope<T>(f: impl FnOnce() -> T) -> T {
    f()
}
