use cairo_vm::{
    felt::{felt_str, Felt252},
    vm::runners::cairo_runner::ExecutionResources,
};
use lazy_static::lazy_static;
use num_traits::Zero;
use starknet_in_rust::EntryPointType;
use starknet_in_rust::{
    core::contract_address::compute_deprecated_class_hash,
    definitions::{
        block_context::StarknetChainId, constants::CONSTRUCTOR_ENTRY_POINT_SELECTOR,
        transaction_type::TransactionType,
    },
    execution::{CallInfo, CallType, TransactionExecutionInfo},
    hash_utils::calculate_contract_address,
    services::api::contract_classes::deprecated_contract_class::ContractClass,
    state::in_memory_state_reader::InMemoryStateReader,
    state::{cached_state::CachedState, state_api::State},
    transaction::DeployAccount,
    utils::Address,
    CasmContractClass,
};
use std::{collections::HashSet, sync::Arc};

lazy_static! {
    static ref TEST_ACCOUNT_COMPILED_CONTRACT_CLASS_HASH: Felt252 = felt_str!("1");
}

#[test]
fn internal_deploy_account() {
    let state_reader = Arc::new(InMemoryStateReader::default());
    let mut state = CachedState::new(state_reader, None, None);

    state.set_contract_classes(Default::default()).unwrap();

    let contract_class =
        ContractClass::from_path("starknet_programs/account_without_validation.json").unwrap();

    let class_hash = compute_deprecated_class_hash(&contract_class).unwrap();
    let class_hash_bytes = class_hash.to_be_bytes();

    state
        .set_contract_class(&class_hash_bytes, &contract_class)
        .unwrap();

    let contract_address_salt =
        felt_str!("2669425616857739096022668060305620640217901643963991674344872184515580705509");

    let internal_deploy_account = DeployAccount::new(
        class_hash_bytes,
        0,
        0.into(),
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
        contract_address_salt.clone(),
        StarknetChainId::TestNet.to_felt(),
    )
    .unwrap();

    let tx_info = internal_deploy_account
        .execute(&mut state, &Default::default())
        .unwrap();

    let contract_address = calculate_contract_address(
        &contract_address_salt,
        &class_hash,
        &[],
        Address(Felt252::zero()),
    )
    .unwrap();

    assert_eq!(
        tx_info,
        TransactionExecutionInfo::new(
            None,
            Some(CallInfo {
                call_type: Some(CallType::Call),
                contract_address: Address(contract_address),
                class_hash: Some(class_hash_bytes),
                entry_point_selector: Some(CONSTRUCTOR_ENTRY_POINT_SELECTOR.clone()),
                entry_point_type: Some(EntryPointType::Constructor),
                ..Default::default()
            }),
            None,
            None,
            0,
            [
                ("n_steps", 3612),
                ("pedersen_builtin", 23),
                ("range_check_builtin", 83),
                ("l1_gas_usage", 3672)
            ]
            .into_iter()
            .map(|(k, v)| (k.to_string(), v))
            .collect(),
            Some(TransactionType::DeployAccount),
        ),
    );
}

#[test]
fn internal_deploy_account_cairo1() {
    let state_reader = Arc::new(InMemoryStateReader::default());
    let mut state = CachedState::new(state_reader, None, Some(Default::default()));

    state.set_contract_classes(Default::default()).unwrap();

    #[cfg(not(feature = "cairo_1_tests"))]
    let program_data = include_bytes!("../starknet_programs/cairo2/hello_world_account.casm");
    #[cfg(feature = "cairo_1_tests")]
    let program_data = include_bytes!("../starknet_programs/cairo1/hello_world_account.casm");
    let contract_class: CasmContractClass = serde_json::from_slice(program_data).unwrap();

    state
        .set_compiled_class(
            &TEST_ACCOUNT_COMPILED_CONTRACT_CLASS_HASH.clone(),
            contract_class,
        )
        .unwrap();

    let contract_address_salt =
        felt_str!("2669425616857739096022668060305620640217901643963991674344872184515580705509");

    let internal_deploy_account = DeployAccount::new(
        TEST_ACCOUNT_COMPILED_CONTRACT_CLASS_HASH
            .clone()
            .to_be_bytes(),
        0,
        1.into(),
        Felt252::zero(),
        vec![2.into()],
        vec![
            felt_str!(
                "3233776396904427614006684968846859029149676045084089832563834729503047027074"
            ),
            felt_str!(
                "707039245213420890976709143988743108543645298941971188668773816813012281203"
            ),
        ],
        contract_address_salt,
        StarknetChainId::TestNet.to_felt(),
    )
    .unwrap();

    let tx_info = internal_deploy_account
        .execute(&mut state, &Default::default())
        .unwrap();

    let accessed_keys: [u8; 32] = [
        3, 178, 128, 25, 204, 253, 189, 48, 255, 198, 89, 81, 217, 75, 184, 92, 158, 43, 132, 52,
        17, 26, 0, 11, 90, 253, 83, 60, 230, 95, 87, 164,
    ];
    let keys: HashSet<[u8; 32]> = [accessed_keys].iter().copied().collect();

    let n_steps;
    #[cfg(not(feature = "cairo_1_tests"))]
    {
        n_steps = 3873;
    }
    #[cfg(feature = "cairo_1_tests")]
    {
        n_steps = 3877;
    }

    assert_eq!(
        tx_info,
        TransactionExecutionInfo::new(
            Some(CallInfo {
                caller_address: Address(0.into()),
                call_type: Some(CallType::Call),
                contract_address: Address(felt_str!(
                    "397149464972449753182583229366244826403270781177748543857889179957856017275"
                )),
                code_address: None,
                #[cfg(not(feature="cairo_1_tests"))]
                gas_consumed: 16440,
                #[cfg(feature="cairo_1_tests")]
                gas_consumed: 16770,
                class_hash: Some([
                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                    0, 0, 0, 0, 0, 1
                ]),
                entry_point_selector: Some(felt_str!(
                    "1554466106298962091002569854891683800203193677547440645928814916929210362005"
                )),
                entry_point_type: Some(EntryPointType::External),
                calldata: vec![
                    1.into(),
                   felt_str!("2669425616857739096022668060305620640217901643963991674344872184515580705509"),
                    2.into()
                ],
                retdata: vec![felt_str!("370462705988")],
                execution_resources: Some(ExecutionResources {
                    #[cfg(not(feature="cairo_1_tests"))]
                    n_steps: 152,
                    #[cfg(feature="cairo_1_tests")]
                    n_steps: 155,
                    n_memory_holes: 17,
                    builtin_instance_counter:
                    [
                    ("range_check_builtin", 2),
                    ]
                .into_iter()
                .map(|(k, v)| (k.to_string(), v))
                .collect(),
            }),

                ..Default::default() }),

            Some(CallInfo {
                call_type: Some(CallType::Call),
                contract_address: Address(felt_str!(
                    "397149464972449753182583229366244826403270781177748543857889179957856017275"
                )),
                class_hash: Some(
                    TEST_ACCOUNT_COMPILED_CONTRACT_CLASS_HASH
                        .clone()
                        .to_be_bytes()
                ),
                entry_point_selector: Some(felt_str!("1159040026212278395030414237414753050475174923702621880048416706425641521556")),
                entry_point_type: Some(EntryPointType::Constructor),
                #[cfg(not(feature="cairo_1_tests"))]
                gas_consumed: 14240,
                #[cfg(feature="cairo_1_tests")]
                gas_consumed: 14350,
                calldata: vec![2.into()],
                accessed_storage_keys: keys,
                execution_resources: Some(ExecutionResources {
                    #[cfg(not(feature="cairo_1_tests"))]
                    n_steps: 92,
                    #[cfg(feature="cairo_1_tests")]
                    n_steps: 93,
                    n_memory_holes: 0,
                    builtin_instance_counter:
                    [
                        ("range_check_builtin", 2),
                    ]
                .into_iter()
                .map(|(k, v)| (k.to_string(), v))
                .collect(),
            }),
                ..Default::default()
            }),
            None,
            None,
            0,
            [
                ("n_steps", n_steps),
                ("pedersen_builtin", 23),
                ("range_check_builtin", 87),
                ("l1_gas_usage", 4896)
            ]
            .into_iter()
            .map(|(k, v)| (k.to_string(), v))
            .collect(),
            Some(TransactionType::DeployAccount),
        ),
    );
}
