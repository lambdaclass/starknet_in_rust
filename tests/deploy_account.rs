#[test]
fn internal_deploy_account() {
    // TransactionExecutionInfo(
    //     validate_info=CallInfo(
    //         caller_address=0,
    //         call_type=<CallType.CALL: 0>,
    //         contract_address=3101457624196293402575328692069750192047331526701739176022857693116787171577,
    //         class_hash=b'\x06\xf5\x00\xf5\'5]\xfd\xb8\t<\x7f\xe4nos\xc9j\x86s\x92\xb4\x9f\xa4\x15zuu8\x92\x859',
    //         entry_point_selector=1554466106298962091002569854891683800203193677547440645928814916929210362005,
    //         entry_point_type=<EntryPointType.EXTERNAL: 0>,
    //         calldata=[
    //             3146761231686369291210245479075933162526514193311043598334639064078158562617,
    //             1270613517460229400092307259346046164583999162596217778923975224016082532624,
    //             1913718131678070017016943142445184252288643009223951525647938775192633419349
    //         ],
    //         retdata=[],
    //         execution_resources=ExecutionResources(
    //             n_steps=75,
    //             builtin_instance_counter={'ecdsa_builtin': 1},
    //             n_memory_holes=0),
    //             events=[],
    //             l2_to_l1_messages=[],
    //             storage_read_values=[1913718131678070017016943142445184252288643009223951525647938775192633419349],
    //             accessed_storage_keys={1672321442399497129215646424919402195095307045612040218489019266998007191460},
    //             internal_calls=[],
    //             code_address=None
    //         ),
    //         call_info=CallInfo(
    //             caller_address=0,
    //             call_type=<CallType.CALL: 0>,
    //             contract_address=3101457624196293402575328692069750192047331526701739176022857693116787171577,
    //             class_hash=b'\x06\xf5\x00\xf5\'5]\xfd\xb8\t<\x7f\xe4nos\xc9j\x86s\x92\xb4\x9f\xa4\x15zuu8\x92\x859',
    //             entry_point_selector=1159040026212278395030414237414753050475174923702621880048416706425641521556,
    //             entry_point_type=<EntryPointType.CONSTRUCTOR: 2>,
    //             calldata=[1913718131678070017016943142445184252288643009223951525647938775192633419349],
    //             retdata=[],
    //             execution_resources=ExecutionResources(
    //                 n_steps=41,
    //                 builtin_instance_counter={},
    //                 n_memory_holes=0
    //             ),
    //             events=[],
    //             l2_to_l1_messages=[],
    //             storage_read_values=[0],
    //             accessed_storage_keys={1672321442399497129215646424919402195095307045612040218489019266998007191460},
    //             internal_calls=[],
    //             code_address=None
    //         ),
    //         fee_transfer_info=CallInfo(caller_address=3101457624196293402575328692069750192047331526701739176022857693116787171577,
    //         call_type=<CallType.CALL: 0>,
    //         contract_address=2087021424722619777119509474943472645767659996348769578120564519014510906823,
    //         class_hash=b'\x06\xa2+\xf6<{\xc0~\xff\xa3\x9a%\xdf\xbd!R=!\x1d\xb0\x10\n\n\xfd\x05M\x17+\x81\x84\x0e\xaf',
    //         entry_point_selector=232670485425082704932579856502088130646006032362877466777181098476241604910,
    //         entry_point_type=<EntryPointType.EXTERNAL: 0>,
    //         calldata=[
    //             1556746869602934183907209817909870193193832701883543897870108478262537288705,
    //             506300000000000,
    //             0
    //         ],
    //         retdata=[1],
    //         execution_resources=ExecutionResources(
    //             n_steps=578,
    //             builtin_instance_counter={
    //                 'pedersen_builtin': 4,
    //                 'range_check_builtin': 29
    //             },
    //             n_memory_holes=42
    //         ),
    //         events=[
    //             OrderedEvent(
    //                 order=0,
    //                 keys=[271746229759260285552388728919865295615886751538523744128730118297934206697],
    //                 data=[
    //                     3101457624196293402575328692069750192047331526701739176022857693116787171577,
    //                     1556746869602934183907209817909870193193832701883543897870108478262537288705,
    //                     506300000000000,
    //                     0
    //                 ]
    //             )
    //         ],
    //         l2_to_l1_messages=[],
    //         storage_read_values=[
    //             9999999999999999999999999999,
    //             0,
    //             9999999999999999999999999999,
    //             0,
    //             513200000000000,
    //             0,
    //             513200000000000,
    //             0
    //         ],
    //         accessed_storage_keys={
    //             314917066383259708268043760188898424426522044853795232244759819372108679877,
    //             314917066383259708268043760188898424426522044853795232244759819372108679878,
    //             2680310865688727396245328826541432461400169267356139026122331450251939194148,
    //             2680310865688727396245328826541432461400169267356139026122331450251939194149
    //         },
    //         internal_calls=[],
    //         code_address=None
    //     ),
    //     actual_fee=506300000000000,
    //     actual_resources={
    //         'ecdsa_builtin': 1,
    //         'l1_gas_usage': 4896,
    //         'n_steps': 3328,
    //         'pedersen_builtin': 23,
    //         'range_check_builtin': 74
    //     },
    //     tx_type=<TransactionType.DEPLOY_ACCOUNT: 2>
    // )

    todo!()
}
