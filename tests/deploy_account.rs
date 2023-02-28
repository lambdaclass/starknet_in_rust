#![deny(warnings)]

use felt::felt_str;
use starknet_rs::{
    business_logic::{
        execution::objects::{CallInfo, CallType, TransactionExecutionInfo},
        fact_state::in_memory_state_reader::InMemoryStateReader,
        state::{cached_state::CachedState, state_api::State},
        transaction::internal_objects::InternalDeployAccount,
    },
    definitions::transaction_type::TransactionType,
    services::api::contract_class::{ContractClass, EntryPointType},
    starknet_storage::dict_storage::DictStorage,
    utils::{felt_to_hash, Address},
};
use std::path::PathBuf;

#[test]
fn internal_deploy_account() {
    let state_reader = InMemoryStateReader::new(DictStorage::new(), DictStorage::new());
    let mut state = CachedState::new(state_reader, None);

    state.set_contract_classes(Default::default()).unwrap();

    let class_hash = felt_to_hash(&felt_str!(
        "3146761231686369291210245479075933162526514193311043598334639064078158562617"
    ));
    let contract_class = ContractClass::try_from(PathBuf::from(
        "starknet_programs/account_without_validation.json",
    ))
    .unwrap();

    state
        .set_contract_class(&class_hash, &contract_class)
        .unwrap();

    let internal_deploy_account = InternalDeployAccount::new(
        class_hash,
        0,
        0, // TODO: Value 340282366920938463463374607431768211457 is too large.
        0,
        vec![
            // TODO: Doesn't work with constructor_calldata not being empty.
            /*felt_str!("2612640184215060329973671567201105979048071207288945836837601213263070089980")*/
        ],
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
        felt_str!("1536727068981429685321"),
    )
    .unwrap();

    let tx_info = internal_deploy_account
        ._apply_specific_concurrent_changes(&mut state, &Default::default())
        .unwrap();

    assert_eq!(
        tx_info,
        TransactionExecutionInfo::new(
            // TODO: Validate.
            None,
            // Some(CallInfo {
            //     caller_address: Address::default(),
            //     call_type: Some(CallType::Call),
            //     contract_address: Address(felt_str!(
            //         "2834350553362882516851133361473202169970201739923129264599307855952863005935"
            //     )),
            //     code_address: None,
            //     class_hash: Some(*b"\x06\xf5\x00\xf5'5]\xfd\xb8\t<\x7f\xe4nos\xc9j\x86s\x92\xb4\x9f\xa4\x15zuu8\x92\x859"),
            //     entry_point_selector: Some(felt_str!("1554466106298962091002569854891683800203193677547440645928814916929210362005")),
            //     entry_point_type: Some(EntryPointType::External),
            //     calldata: vec![
            //         felt_str!("3146761231686369291210245479075933162526514193311043598334639064078158562617"),
            //         felt_str!("2669425616857739096022668060305620640217901643963991674344872184515580705509"),
            //         felt_str!("2612640184215060329973671567201105979048071207288945836837601213263070089980"),
            //     ],
            //     retdata: vec!(),
            //     execution_resources: ExecutionResources {
            //         n_steps: 75,
            //         n_memory_holes: 8,
            //         builtin_instance_counter: [("ecdsa_builtin", 1)]
            //         .into_iter()
            //         .map(|(k, v)| (k.to_string(), v))
            //         .collect()
            //     },
            //     events: vec!(),
            //     l2_to_l1_messages: vec![],
            //     storage_read_values: vec![felt_str!("2612640184215060329973671567201105979048071207288945836837601213263070089980")],
            //     accessed_storage_keys: [felt_to_hash(&felt_str!("1672321442399497129215646424919402195095307045612040218489019266998007191460"))].into_iter().collect(),
            //     internal_calls: vec!(),
            // }),
            Some(CallInfo {
                call_type: Some(CallType::Call),
                // TODO: Contract address.
                contract_address: Address(felt_str!("1351769743764599227746416364615306404319526869558988948822078481252102329345")),
                // contract_address: Address(felt_str!(
                //     "2834350553362882516851133361473202169970201739923129264599307855952863005935"
                // )),
                class_hash: Some(*b"\x06\xf5\x00\xf5'5]\xfd\xb8\t<\x7f\xe4nos\xc9j\x86s\x92\xb4\x9f\xa4\x15zuu8\x92\x859"),
                // TODO: Entry point selector.
                // entry_point_selector: Some(felt_str!("1159040026212278395030414237414753050475174923702621880048416706425641521556")),
                entry_point_type: Some(EntryPointType::Constructor),
                // TODO: Constructor calldata.
                // calldata: vec![felt_str!("2612640184215060329973671567201105979048071207288945836837601213263070089980")],
                // TODO: Execution resources.
                // execution_resources: ExecutionResources {
                //     n_steps: 41,
                //     ..Default::default()
                // },
                // TODO: Storage read values.
                // storage_read_values: vec![Felt::zero()],
                // TODO: Storage accessed keys.
                // accessed_storage_keys: [felt_to_hash(&felt_str!("1672321442399497129215646424919402195095307045612040218489019266998007191460"))].into_iter().collect(),
                ..Default::default()
            }),
            None,
            0,
            [
                ("l1_gas_usage", 1224),
                // TODO: Actual resources.
                // ("l1_gas_usage", 4896),
                // ("pedersen_builtin", 23),
                // ("range_check_builtin", 74),
                // ("ecdsa_builtin", 1),
                // ("n_steps", 3328),
            ]
            .into_iter()
            .map(|(k, v)| (k.to_string(), v))
            .collect(),
            Some(TransactionType::DeployAccount),
        ),
    );
}
