pub mod rpc_state;
pub mod utils;

#[cfg(test)]
mod tests {
    use crate::rpc_state::*;
    use cairo_vm::vm::runners::cairo_runner::ExecutionResources;
    use pretty_assertions_sorted::{assert_eq, assert_eq_sorted};
    use starknet_api::{
        class_hash,
        core::{ClassHash, ContractAddress, PatriciaKey},
        hash::{StarkFelt, StarkHash},
        patricia_key, stark_felt,
        state::StorageKey,
        transaction::{Transaction as SNTransaction, TransactionHash},
    };
    use starknet_in_rust::{
        definitions::block_context::StarknetChainId, transaction::InvokeFunction,
    };
    use std::collections::HashMap;

    /// A utility macro to create a [`ContractAddress`] from a hex string / unsigned integer
    /// representation.
    /// Imported from starknet_api
    macro_rules! contract_address {
        ($s:expr) => {
            ContractAddress(patricia_key!($s))
        };
    }

    #[test]
    fn test_get_contract_class_cairo1() {
        let rpc_state = RpcState::new_infura(RpcChain::MainNet, BlockTag::Latest.into());

        let class_hash =
            class_hash!("0298e56befa6d1446b86ed5b900a9ba51fd2faa683cd6f50e8f833c0fb847216");
        // This belongs to
        // https://starkscan.co/class/0x0298e56befa6d1446b86ed5b900a9ba51fd2faa683cd6f50e8f833c0fb847216
        // which is cairo1.0

        rpc_state.get_contract_class(&class_hash);
    }

    #[test]
    fn test_get_contract_class_cairo0() {
        let rpc_state = RpcState::new_infura(RpcChain::MainNet, BlockTag::Latest.into());

        let class_hash =
            class_hash!("025ec026985a3bf9d0cc1fe17326b245dfdc3ff89b8fde106542a3ea56c5a918");
        rpc_state.get_contract_class(&class_hash);
    }

    #[test]
    fn test_get_class_hash_at() {
        let rpc_state = RpcState::new_infura(RpcChain::MainNet, BlockTag::Latest.into());
        let address =
            contract_address!("00b081f7ba1efc6fe98770b09a827ae373ef2baa6116b3d2a0bf5154136573a9");

        assert_eq!(
            rpc_state.get_class_hash_at(&address),
            class_hash!("025ec026985a3bf9d0cc1fe17326b245dfdc3ff89b8fde106542a3ea56c5a918")
        );
    }

    #[test]
    fn test_get_nonce_at() {
        let rpc_state = RpcState::new_infura(RpcChain::TestNet, BlockTag::Latest.into());
        // Contract deployed by xqft which will not be used again, so nonce changes will not break
        // this test.
        let address =
            contract_address!("07185f2a350edcc7ea072888edb4507247de23e710cbd56084c356d265626bea");
        assert_eq!(rpc_state.get_nonce_at(&address), stark_felt!("0x0"));
    }

    #[test]
    fn test_get_storage_at() {
        let rpc_state = RpcState::new_infura(RpcChain::MainNet, BlockTag::Latest.into());
        let address =
            contract_address!("00b081f7ba1efc6fe98770b09a827ae373ef2baa6116b3d2a0bf5154136573a9");
        let key = StorageKey(patricia_key!(0u128));

        assert_eq_sorted!(rpc_state.get_storage_at(&address, &key), stark_felt!("0x0"));
    }

    #[test]
    fn test_get_transaction() {
        let rpc_state = RpcState::new_infura(RpcChain::MainNet, BlockTag::Latest.into());
        let tx_hash = TransactionHash(stark_felt!(
            "06da92cfbdceac5e5e94a1f40772d6c79d34f011815606742658559ec77b6955"
        ));

        rpc_state.get_transaction(&tx_hash);
    }

    #[test]
    fn test_try_from_invoke() {
        let rpc_state = RpcState::new_infura(RpcChain::MainNet, BlockTag::Latest.into());
        let tx_hash = TransactionHash(stark_felt!(
            "06da92cfbdceac5e5e94a1f40772d6c79d34f011815606742658559ec77b6955"
        ));

        let tx = rpc_state.get_transaction(&tx_hash);
        match tx {
            SNTransaction::Invoke(tx) => {
                InvokeFunction::from_invoke_transaction(tx, StarknetChainId::MainNet)
            }
            _ => unreachable!(),
        }
        .unwrap();
    }

    #[test]
    fn test_get_block_info() {
        let rpc_state = RpcState::new_infura(RpcChain::MainNet, BlockTag::Latest.into());

        rpc_state.get_block_info();
    }

    // Tested with the following query to the Feeder Gateway API:
    // https://alpha4-2.starknet.io/feeder_gateway/get_transaction_trace?transactionHash=0x019feb888a2d53ffddb7a1750264640afab8e9c23119e648b5259f1b5e7d51bc
    #[test]
    fn test_get_transaction_trace() {
        let rpc_state = RpcState::new_infura(RpcChain::TestNet2, BlockTag::Latest.into());

        let tx_hash = TransactionHash(stark_felt!(
            "19feb888a2d53ffddb7a1750264640afab8e9c23119e648b5259f1b5e7d51bc"
        ));

        let tx_trace = rpc_state.get_transaction_trace(&tx_hash);

        assert_eq!(
            tx_trace.signature,
            vec![
                stark_felt!("ffab1c47d8d5e5b76bdcc4af79e98205716c36b440f20244c69599a91ace58"),
                stark_felt!("6aa48a0906c9c1f7381c1a040c043b649eeac1eea08f24a9d07813f6b1d05fe"),
            ]
        );

        assert_eq!(
            tx_trace.validate_invocation.calldata,
            Some(vec![
                stark_felt!("1"),
                stark_felt!("690c876e61beda61e994543af68038edac4e1cb1990ab06e52a2d27e56a1232"),
                stark_felt!("1f24f689ced5802b706d7a2e28743fe45c7bfa37431c97b1c766e9622b65573"),
                stark_felt!("0"),
                stark_felt!("9"),
                stark_felt!("9"),
                stark_felt!("4"),
                stark_felt!("4254432d55534443"),
                stark_felt!("f02e7324ecbd65ce267"),
                stark_felt!("5754492d55534443"),
                stark_felt!("8e13050d06d8f514c"),
                stark_felt!("4554482d55534443"),
                stark_felt!("f0e4a142c3551c149d"),
                stark_felt!("4a50592d55534443"),
                stark_felt!("38bd34c31a0a5c"),
            ])
        );
        assert_eq!(tx_trace.validate_invocation.retdata, Some(vec![]));
        assert_eq_sorted!(
            tx_trace.validate_invocation.execution_resources,
            ExecutionResources {
                n_steps: 790,
                n_memory_holes: 51,
                builtin_instance_counter: HashMap::from([
                    ("range_check_builtin".to_string(), 20),
                    ("ecdsa_builtin".to_string(), 1),
                    ("pedersen_builtin".to_string(), 2),
                ]),
            }
        );
        assert_eq!(tx_trace.validate_invocation.internal_calls.len(), 1);

        assert_eq!(
            tx_trace.function_invocation.as_ref().unwrap().calldata,
            Some(vec![
                stark_felt!("1"),
                stark_felt!("690c876e61beda61e994543af68038edac4e1cb1990ab06e52a2d27e56a1232"),
                stark_felt!("1f24f689ced5802b706d7a2e28743fe45c7bfa37431c97b1c766e9622b65573"),
                stark_felt!("0"),
                stark_felt!("9"),
                stark_felt!("9"),
                stark_felt!("4"),
                stark_felt!("4254432d55534443"),
                stark_felt!("f02e7324ecbd65ce267"),
                stark_felt!("5754492d55534443"),
                stark_felt!("8e13050d06d8f514c"),
                stark_felt!("4554482d55534443"),
                stark_felt!("f0e4a142c3551c149d"),
                stark_felt!("4a50592d55534443"),
                stark_felt!("38bd34c31a0a5c"),
            ])
        );
        assert_eq!(
            tx_trace.function_invocation.as_ref().unwrap().retdata,
            Some(vec![0u128.into()])
        );
        assert_eq_sorted!(
            tx_trace
                .function_invocation
                .as_ref()
                .unwrap()
                .execution_resources,
            ExecutionResources {
                n_steps: 2808,
                n_memory_holes: 136,
                builtin_instance_counter: HashMap::from([
                    ("range_check_builtin".to_string(), 49),
                    ("pedersen_builtin".to_string(), 14),
                ]),
            }
        );
        assert_eq!(
            tx_trace
                .function_invocation
                .as_ref()
                .unwrap()
                .internal_calls
                .len(),
            1
        );
        assert_eq!(
            tx_trace
                .function_invocation
                .as_ref()
                .unwrap()
                .internal_calls[0]
                .internal_calls
                .len(),
            1
        );
        assert_eq!(
            tx_trace
                .function_invocation
                .as_ref()
                .unwrap()
                .internal_calls[0]
                .internal_calls[0]
                .internal_calls
                .len(),
            7
        );

        assert_eq!(
            tx_trace.fee_transfer_invocation.calldata,
            Some(vec![
                stark_felt!("1176a1bd84444c89232ec27754698e5d2e7e1a7f1539f12027f28b23ec9f3d8"),
                stark_felt!("2b0322a23ba4"),
                stark_felt!("0"),
            ])
        );
        assert_eq!(
            tx_trace.fee_transfer_invocation.retdata,
            Some(vec![1u128.into()])
        );
        assert_eq_sorted!(
            tx_trace.fee_transfer_invocation.execution_resources,
            ExecutionResources {
                n_steps: 586,
                n_memory_holes: 42,
                builtin_instance_counter: HashMap::from([
                    ("range_check_builtin".to_string(), 21),
                    ("pedersen_builtin".to_string(), 4),
                ]),
            }
        );
        assert_eq!(tx_trace.fee_transfer_invocation.internal_calls.len(), 1);
    }

    #[test]
    fn test_get_transaction_receipt() {
        let rpc_state = RpcState::new_infura(RpcChain::MainNet, BlockTag::Latest.into());
        let tx_hash = TransactionHash(stark_felt!(
            "06da92cfbdceac5e5e94a1f40772d6c79d34f011815606742658559ec77b6955"
        ));

        rpc_state.get_transaction_receipt(&tx_hash);
    }
}

mod blockifier_transaction_tests {
    use super::*;
    use crate::rpc_state::{
        RpcBlockInfo, RpcChain, RpcState, RpcTransactionReceipt, TransactionTrace,
    };
    use blockifier::{
        block_context::BlockContext,
        execution::contract_class::{ContractClass, ContractClassV0, ContractClassV0Inner},
        state::{
            cached_state::{CachedState, GlobalContractCache},
            state_api::{StateReader, StateResult},
        },
        transaction::{
            account_transaction::AccountTransaction,
            objects::TransactionExecutionInfo,
            transactions::{ExecutableTransaction, InvokeTransaction},
        },
    };
    use cairo_vm::types::program::Program;
    use starknet_api::{
        block::BlockNumber,
        contract_address,
        core::{ClassHash, CompiledClassHash, ContractAddress, Nonce, PatriciaKey},
        hash::{StarkFelt, StarkHash},
        patricia_key, stark_felt,
        state::StorageKey,
        transaction::{Transaction as SNTransaction, TransactionHash},
    };
    use starknet_in_rust::CasmContractClass;
    use std::{collections::HashMap, sync::Arc};

    pub struct RpcStateReader(RpcState);

    impl StateReader for RpcStateReader {
        fn get_storage_at(
            &mut self,
            contract_address: ContractAddress,
            key: StorageKey,
        ) -> StateResult<StarkFelt> {
            Ok(self.0.get_storage_at(&contract_address, &key))
        }

        fn get_nonce_at(&mut self, contract_address: ContractAddress) -> StateResult<Nonce> {
            Ok(Nonce(self.0.get_nonce_at(&contract_address)))
        }

        fn get_class_hash_at(
            &mut self,
            contract_address: ContractAddress,
        ) -> StateResult<ClassHash> {
            Ok(self.0.get_class_hash_at(&contract_address))
        }

        /// Returns the contract class of the given class hash.
        fn get_compiled_contract_class(
            &mut self,
            class_hash: &ClassHash,
        ) -> StateResult<ContractClass> {
            Ok(match self.0.get_contract_class(class_hash) {
                starknet::core::types::ContractClass::Legacy(compressed_legacy_cc) => {
                    let as_str = utils::decode_reader(compressed_legacy_cc.program).unwrap();
                    let program = Program::from_bytes(as_str.as_bytes(), None).unwrap();
                    let entry_points_by_type = utils::map_entry_points_by_type_legacy(
                        compressed_legacy_cc.entry_points_by_type,
                    );
                    let inner = Arc::new(ContractClassV0Inner {
                        program,
                        entry_points_by_type,
                    });
                    blockifier::execution::contract_class::ContractClass::V0(ContractClassV0(inner))
                }
                starknet::core::types::ContractClass::Sierra(flattened_sierra_cc) => {
                    let middle_sierra: utils::MiddleSierraContractClass = {
                        let v = serde_json::to_value(flattened_sierra_cc).unwrap();
                        serde_json::from_value(v).unwrap()
                    };
                    let sierra_cc = cairo_lang_starknet::contract_class::ContractClass {
                        sierra_program: middle_sierra.sierra_program,
                        contract_class_version: middle_sierra.contract_class_version,
                        entry_points_by_type: middle_sierra.entry_points_by_type,
                        sierra_program_debug_info: None,
                        abi: None,
                    };
                    let casm_cc = CasmContractClass::from_contract_class(sierra_cc, false).unwrap();
                    blockifier::execution::contract_class::ContractClass::V1(
                        casm_cc.try_into().unwrap(),
                    )
                }
            })
        }

        /// Returns the compiled class hash of the given class hash.
        fn get_compiled_class_hash(
            &mut self,
            class_hash: ClassHash,
        ) -> StateResult<CompiledClassHash> {
            Ok(CompiledClassHash(
                self.0
                    .get_class_hash_at(&ContractAddress(class_hash.0.try_into().unwrap()))
                    .0,
            ))
        }
    }

    #[allow(unused)]
    pub fn execute_tx(
        tx_hash: &str,
        network: RpcChain,
        block_number: BlockNumber,
    ) -> (
        TransactionExecutionInfo,
        TransactionTrace,
        RpcTransactionReceipt,
    ) {
        let tx_hash = tx_hash.strip_prefix("0x").unwrap();

        // Instantiate the RPC StateReader and the CachedState
        let rpc_reader = RpcStateReader(RpcState::new_infura(network, block_number.into()));
        let gas_price = rpc_reader.0.get_gas_price(block_number.0).unwrap();

        // Get values for block context before giving ownership of the reader
        let chain_id = rpc_reader.0.get_chain_name();
        let RpcBlockInfo {
            block_number,
            block_timestamp,
            sequencer_address,
            ..
        } = rpc_reader.0.get_block_info();

        // Get transaction before giving ownership of the reader
        let tx_hash = TransactionHash(stark_felt!(tx_hash));
        let sn_api_tx = rpc_reader.0.get_transaction(&tx_hash);

        let trace = rpc_reader.0.get_transaction_trace(&tx_hash);
        let receipt = rpc_reader.0.get_transaction_receipt(&tx_hash);

        // Create state from RPC reader
        let global_cache = GlobalContractCache::default();
        let mut state = CachedState::new(rpc_reader, global_cache);

        let fee_token_address =
            contract_address!("049d36570d4e46f48e99674bd3fcc84644ddd6b96f7c741b1562b82f9e004dc7");

        const N_STEPS_FEE_WEIGHT: f64 = 0.01;
        let vm_resource_fee_cost = Arc::new(HashMap::from([
            ("n_steps".to_string(), N_STEPS_FEE_WEIGHT),
            ("output_builtin".to_string(), 0.0),
            ("pedersen_builtin".to_string(), N_STEPS_FEE_WEIGHT * 32.0),
            ("range_check_builtin".to_string(), N_STEPS_FEE_WEIGHT * 16.0),
            ("ecdsa_builtin".to_string(), N_STEPS_FEE_WEIGHT * 2048.0),
            ("bitwise_builtin".to_string(), N_STEPS_FEE_WEIGHT * 64.0),
            ("ec_op_builtin".to_string(), N_STEPS_FEE_WEIGHT * 1024.0),
            ("poseidon_builtin".to_string(), N_STEPS_FEE_WEIGHT * 32.0),
            (
                "segment_arena_builtin".to_string(),
                N_STEPS_FEE_WEIGHT * 10.0,
            ),
            ("keccak_builtin".to_string(), N_STEPS_FEE_WEIGHT * 2048.0), // 2**11
        ]));

        let block_context = BlockContext {
            chain_id,
            block_number,
            block_timestamp,
            sequencer_address,
            fee_token_address,
            vm_resource_fee_cost,
            gas_price,
            invoke_tx_max_n_steps: 1_000_000,
            validate_max_n_steps: 1_000_000,
            max_recursion_depth: 500,
        };

        // Map starknet_api transaction to blockifier's
        let blockifier_tx = match sn_api_tx {
            SNTransaction::Invoke(tx) => {
                let invoke = InvokeTransaction { tx, tx_hash };
                AccountTransaction::Invoke(invoke)
            }
            _ => unimplemented!(),
        };

        (
            blockifier_tx
                .execute(&mut state, &block_context, true, true)
                .unwrap(),
            trace,
            receipt,
        )
    }

    #[cfg(test)]
    mod test {
        use super::*;
        use crate::rpc_state::BlockValue;
        use blockifier::execution::entry_point::CallInfo;

        #[test]
        fn test_get_gas_price() {
            let block = BlockValue::Number(BlockNumber(169928));
            let rpc_state = RpcState::new_infura(RpcChain::MainNet, block);

            let price = rpc_state.get_gas_price(169928).unwrap();
            assert_eq!(price, 22804578690);
        }

        #[test]
        fn test_recent_tx() {
            let (tx_info, trace, receipt) = execute_tx(
                "0x05d200ef175ba15d676a68b36f7a7b72c17c17604eda4c1efc2ed5e4973e2c91",
                RpcChain::MainNet,
                BlockNumber(169928),
            );

            let TransactionExecutionInfo {
                execute_call_info,
                actual_fee,
                ..
            } = tx_info;

            let CallInfo {
                vm_resources,
                inner_calls,
                ..
            } = execute_call_info.unwrap();

            assert_eq!(actual_fee.0, receipt.actual_fee);
            assert_eq!(
                vm_resources,
                trace
                    .function_invocation
                    .as_ref()
                    .unwrap()
                    .execution_resources
            );
            assert_eq!(
                inner_calls.len(),
                trace
                    .function_invocation
                    .as_ref()
                    .unwrap()
                    .internal_calls
                    .len()
            );
        }
    }
}

mod starknet_in_rust_transaction_tests {
    use crate::rpc_state::{
        RpcBlockInfo, RpcChain, RpcState, RpcTransactionReceipt, TransactionTrace,
    };
    use cairo_vm::felt::{felt_str, Felt252};
    use starknet_api::{
        block::BlockNumber,
        core::{ContractAddress, PatriciaKey},
        hash::{StarkFelt, StarkHash},
        stark_felt,
        state::StorageKey,
        transaction::{Transaction, TransactionHash},
    };
    use starknet_in_rust::{
        core::errors::state_errors::StateError,
        definitions::{
            block_context::{BlockContext, StarknetChainId, StarknetOsConfig},
            constants::{
                DEFAULT_CAIRO_RESOURCE_FEE_WEIGHTS,
                DEFAULT_CONTRACT_STORAGE_COMMITMENT_TREE_HEIGHT,
                DEFAULT_GLOBAL_STATE_COMMITMENT_TREE_HEIGHT, DEFAULT_INVOKE_TX_MAX_N_STEPS,
                DEFAULT_VALIDATE_MAX_N_STEPS,
            },
        },
        execution::TransactionExecutionInfo,
        services::api::contract_classes::compiled_class::CompiledClass,
        state::{
            cached_state::{CachedState, ContractClassCache},
            state_api::StateReader,
            state_cache::StorageEntry,
            BlockInfo,
        },
        transaction::InvokeFunction,
        utils::{Address, ClassHash},
    };
    use std::sync::Arc;

    pub struct RpcStateReader(RpcState);

    impl StateReader for RpcStateReader {
        fn get_contract_class(&self, class_hash: &ClassHash) -> Result<CompiledClass, StateError> {
            let hash = starknet_api::core::ClassHash(StarkHash::new(*class_hash).unwrap());
            Ok(CompiledClass::from(self.0.get_contract_class(&hash)))
        }

        fn get_class_hash_at(&self, contract_address: &Address) -> Result<ClassHash, StateError> {
            let address = ContractAddress(
                PatriciaKey::try_from(
                    StarkHash::new(contract_address.clone().0.to_be_bytes()).unwrap(),
                )
                .unwrap(),
            );
            let mut bytes = [0u8; 32];
            bytes.copy_from_slice(self.0.get_class_hash_at(&address).0.bytes());
            Ok(bytes)
        }

        fn get_nonce_at(&self, contract_address: &Address) -> Result<Felt252, StateError> {
            let address = ContractAddress(
                PatriciaKey::try_from(
                    StarkHash::new(contract_address.clone().0.to_be_bytes()).unwrap(),
                )
                .unwrap(),
            );
            let nonce = self.0.get_nonce_at(&address);
            Ok(Felt252::from_bytes_be(nonce.bytes()))
        }
        fn get_storage_at(&self, storage_entry: &StorageEntry) -> Result<Felt252, StateError> {
            let (contract_address, key) = storage_entry;
            let address = ContractAddress(
                PatriciaKey::try_from(
                    StarkHash::new(contract_address.clone().0.to_be_bytes()).unwrap(),
                )
                .unwrap(),
            );
            let key = StorageKey(PatriciaKey::try_from(StarkHash::new(*key).unwrap()).unwrap());
            let value = self.0.get_storage_at(&address, &key);
            Ok(Felt252::from_bytes_be(value.bytes()))
        }
        fn get_compiled_class_hash(&self, class_hash: &ClassHash) -> Result<[u8; 32], StateError> {
            let address = ContractAddress(
                PatriciaKey::try_from(StarkHash::new(*class_hash).unwrap()).unwrap(),
            );
            let mut bytes = [0u8; 32];
            bytes.copy_from_slice(self.0.get_class_hash_at(&address).0.bytes());
            Ok(bytes)
        }
    }

    #[allow(unused)]
    pub fn execute_tx(
        tx_hash: &str,
        network: RpcChain,
        block_number: BlockNumber,
    ) -> (
        TransactionExecutionInfo,
        TransactionTrace,
        RpcTransactionReceipt,
    ) {
        let fee_token_address = Address(felt_str!(
            "049d36570d4e46f48e99674bd3fcc84644ddd6b96f7c741b1562b82f9e004dc7",
            16
        ));

        let tx_hash = tx_hash.strip_prefix("0x").unwrap();

        // Instantiate the RPC StateReader and the CachedState
        let rpc_reader = RpcStateReader(RpcState::new_infura(network, block_number.into()));
        let gas_price = rpc_reader.0.get_gas_price(block_number.0).unwrap();

        // Get values for block context before giving ownership of the reader
        let chain_id = match rpc_reader.0.chain {
            RpcChain::MainNet => StarknetChainId::MainNet,
            RpcChain::TestNet => StarknetChainId::TestNet,
            RpcChain::TestNet2 => StarknetChainId::TestNet2,
        };
        let starknet_os_config =
            StarknetOsConfig::new(chain_id.to_felt(), fee_token_address, gas_price);
        let block_info = {
            let RpcBlockInfo {
                block_number,
                block_timestamp,
                sequencer_address,
                ..
            } = rpc_reader.0.get_block_info();

            let block_number = block_number.0;
            let block_timestamp = block_timestamp.0;
            let sequencer_address =
                Address(Felt252::from_bytes_be(sequencer_address.0.key().bytes()));

            BlockInfo {
                block_number,
                block_timestamp,
                gas_price,
                sequencer_address,
            }
        };

        // Get transaction before giving ownership of the reader
        let tx_hash = TransactionHash(stark_felt!(tx_hash));
        let tx = match rpc_reader.0.get_transaction(&tx_hash) {
            Transaction::Invoke(tx) => starknet_in_rust::transaction::Transaction::InvokeFunction(
                InvokeFunction::from_invoke_transaction(tx, chain_id).unwrap(),
            ),
            _ => unimplemented!(),
        };

        let trace = rpc_reader.0.get_transaction_trace(&tx_hash);
        let receipt = rpc_reader.0.get_transaction_receipt(&tx_hash);

        let class_cache = ContractClassCache::default();
        let mut state = CachedState::new(Arc::new(rpc_reader), class_cache);

        let block_context = BlockContext::new(
            starknet_os_config,
            DEFAULT_CONTRACT_STORAGE_COMMITMENT_TREE_HEIGHT,
            DEFAULT_GLOBAL_STATE_COMMITMENT_TREE_HEIGHT,
            DEFAULT_CAIRO_RESOURCE_FEE_WEIGHTS.clone(),
            DEFAULT_INVOKE_TX_MAX_N_STEPS,
            DEFAULT_VALIDATE_MAX_N_STEPS,
            block_info,
            Default::default(),
            true,
        );

        (
            tx.execute(&mut state, &block_context, u128::MAX).unwrap(),
            trace,
            receipt,
        )
    }

    #[cfg(test)]
    mod test {
        use super::*;
        use crate::rpc_state::{BlockValue, RpcState};
        use starknet_in_rust::execution::CallInfo;

        #[test]
        fn test_get_gas_price() {
            let block = BlockValue::Number(BlockNumber(169928));
            let rpc_state = RpcState::new_infura(RpcChain::MainNet, block);

            let price = rpc_state.get_gas_price(169928).unwrap();
            assert_eq!(price, 22804578690);
        }

        #[test]
        #[ignore = "working on fixes"]
        fn test_recent_tx() {
            let (tx_info, trace, receipt) = execute_tx(
                "0x05d200ef175ba15d676a68b36f7a7b72c17c17604eda4c1efc2ed5e4973e2c91",
                RpcChain::MainNet,
                BlockNumber(169928),
            );

            let TransactionExecutionInfo {
                call_info,
                actual_fee,
                ..
            } = tx_info;

            let CallInfo {
                execution_resources,
                internal_calls,
                ..
            } = call_info.unwrap();

            assert_eq!(
                execution_resources,
                Some(
                    trace
                        .function_invocation
                        .as_ref()
                        .unwrap()
                        .execution_resources
                        .clone()
                )
            );
            assert_eq!(
                internal_calls.len(),
                trace
                    .function_invocation
                    .as_ref()
                    .unwrap()
                    .internal_calls
                    .len()
            );

            assert_eq!(actual_fee, receipt.actual_fee);
        }
    }
}
