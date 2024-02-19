use blockifier::{
    block_context::{BlockContext, FeeTokenAddresses, GasPrices},
    execution::{
        call_info::CallInfo,
        contract_class::{
            ContractClass as BlockifierContractClass, ContractClassV0, ContractClassV0Inner,
        },
    },
    state::{
        cached_state::{CachedState, GlobalContractCache},
        errors::StateError,
        state_api::{StateReader, StateResult},
    },
    transaction::{
        account_transaction::AccountTransaction,
        objects::TransactionExecutionInfo,
        transactions::{
            DeclareTransaction, DeployAccountTransaction, ExecutableTransaction, InvokeTransaction,
            L1HandlerTransaction,
        },
    },
};
use cairo_lang_starknet::{
    casm_contract_class::CasmContractClass, contract_class::ContractClass as SierraContractClass,
};
use cairo_vm_blockifier::types::program::Program;
use pretty_assertions_sorted::assert_eq;
use rpc_state_reader::rpc_state::*;
use rpc_state_reader::utils;
use starknet::core::types::ContractClass as SNContractClass;
use starknet_api::{
    block::BlockNumber,
    contract_address,
    core::{
        calculate_contract_address, ClassHash, CompiledClassHash, ContractAddress, Nonce,
        PatriciaKey,
    },
    hash::{StarkFelt, StarkHash},
    patricia_key, stark_felt,
    state::StorageKey,
    transaction::{Transaction as SNTransaction, TransactionHash},
};
use std::{collections::HashMap, sync::Arc};
use test_case::test_case;

pub struct RpcStateReader(RpcState);

impl StateReader for RpcStateReader {
    fn get_storage_at(
        &mut self,
        contract_address: starknet_api::core::ContractAddress,
        key: StorageKey,
    ) -> StateResult<StarkFelt> {
        Ok(self.0.get_storage_at(&contract_address, &key))
    }

    fn get_nonce_at(&mut self, contract_address: ContractAddress) -> StateResult<Nonce> {
        Ok(Nonce(self.0.get_nonce_at(&contract_address)))
    }

    fn get_class_hash_at(&mut self, contract_address: ContractAddress) -> StateResult<ClassHash> {
        Ok(self.0.get_class_hash_at(&contract_address))
    }

    /// Returns the contract class of the given class hash.
    fn get_compiled_contract_class(
        &mut self,
        class_hash: &ClassHash,
    ) -> StateResult<BlockifierContractClass> {
        Ok(match self.0.get_contract_class(class_hash) {
            Some(SNContractClass::Legacy(compressed_legacy_cc)) => {
                let as_str = utils::decode_reader(compressed_legacy_cc.program).unwrap();
                let program = Program::from_bytes(as_str.as_bytes(), None).unwrap();
                let entry_points_by_type = utils::map_entry_points_by_type_legacy(
                    compressed_legacy_cc.entry_points_by_type,
                );
                let inner = Arc::new(ContractClassV0Inner {
                    program,
                    entry_points_by_type,
                });
                BlockifierContractClass::V0(ContractClassV0(inner))
            }
            Some(SNContractClass::Sierra(flattened_sierra_cc)) => {
                let middle_sierra: utils::MiddleSierraContractClass = {
                    let v = serde_json::to_value(flattened_sierra_cc).unwrap();
                    serde_json::from_value(v).unwrap()
                };
                let sierra_cc = SierraContractClass {
                    sierra_program: middle_sierra.sierra_program,
                    contract_class_version: middle_sierra.contract_class_version,
                    entry_points_by_type: middle_sierra.entry_points_by_type,
                    sierra_program_debug_info: None,
                    abi: None,
                };
                let casm_cc = CasmContractClass::from_contract_class(sierra_cc, false).unwrap();
                BlockifierContractClass::V1(casm_cc.try_into().unwrap())
            }
            None => return Err(StateError::UndeclaredClassHash(*class_hash)),
        })
    }

    /// Returns the compiled class hash of the given class hash.
    fn get_compiled_class_hash(&mut self, class_hash: ClassHash) -> StateResult<CompiledClassHash> {
        Ok(CompiledClassHash(
            self.0
                .get_class_hash_at(&ContractAddress(class_hash.0.try_into().unwrap()))
                .0,
        ))
    }
}

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
    let rpc_reader = RpcStateReader(RpcState::new_rpc(network, block_number.into()).unwrap());
    let gas_price = rpc_reader.0.get_gas_price(block_number.0).unwrap();

    // Get values for block context before giving ownership of the reader
    let chain_id = rpc_reader.0.get_chain_name();
    let RpcBlockInfo {
        block_number,
        block_timestamp,
        sequencer_address,
        ..
    } = rpc_reader.0.get_block_info().unwrap();

    // Get transaction before giving ownership of the reader
    let tx_hash = TransactionHash(stark_felt!(tx_hash));
    let sn_api_tx = rpc_reader.0.get_transaction(&tx_hash);

    let trace = rpc_reader.0.get_transaction_trace(&tx_hash).unwrap();
    let receipt = rpc_reader.0.get_transaction_receipt(&tx_hash).unwrap();

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
        // TODO: Add strk token address when updated
        fee_token_addresses: FeeTokenAddresses {
            strk_fee_token_address: fee_token_address,
            eth_fee_token_address: fee_token_address,
        },
        vm_resource_fee_cost,
        // TODO: Add strk l1 gas price when updated
        gas_prices: GasPrices {
            eth_l1_gas_price: gas_price.eth_l1_gas_price,
            strk_l1_gas_price: gas_price.strk_l1_gas_price,
        },
        invoke_tx_max_n_steps: 1_000_000,
        validate_max_n_steps: 1_000_000,
        max_recursion_depth: 500,
    };

    // Map starknet_api transaction to blockifier's
    let blockifier_tx = match sn_api_tx.unwrap() {
        SNTransaction::Invoke(tx) => {
            let invoke = InvokeTransaction {
                tx,
                tx_hash,
                only_query: false,
            };
            AccountTransaction::Invoke(invoke)
        }
        SNTransaction::DeployAccount(tx) => {
            let contract_address = calculate_contract_address(
                tx.contract_address_salt(),
                tx.class_hash(),
                &tx.constructor_calldata(),
                ContractAddress::default(),
            )
            .unwrap();
            AccountTransaction::DeployAccount(DeployAccountTransaction {
                only_query: false,
                tx,
                tx_hash,
                contract_address,
            })
        }
        SNTransaction::Declare(tx) => {
            // Fetch the contract_class from the next block (as we don't have it in the previous one)
            let mut next_block_state_reader =
                RpcStateReader(RpcState::new_rpc(network, (block_number.next()).into()).unwrap());
            let contract_class = next_block_state_reader
                .get_compiled_contract_class(&tx.class_hash())
                .unwrap();

            let declare = DeclareTransaction::new(tx, tx_hash, contract_class).unwrap();
            AccountTransaction::Declare(declare)
        }
        SNTransaction::L1Handler(tx) => {
            // As L1Hanlder is not an account transaction we execute it here and return the result
            let blockifier_tx = L1HandlerTransaction {
                tx,
                tx_hash,
                paid_fee_on_l1: starknet_api::transaction::Fee(u128::MAX),
            };
            return (
                blockifier_tx
                    .execute(&mut state, &block_context, true, true)
                    .unwrap(),
                trace,
                receipt,
            );
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

#[test]
fn test_get_gas_price() {
    let block = BlockValue::Number(BlockNumber(169928));
    let rpc_state = RpcState::new_rpc(RpcChain::MainNet, block).unwrap();

    let price = rpc_state.get_gas_price(169928).unwrap();
    assert_eq!(price.eth_l1_gas_price, 22804578690);
}

#[test]
#[ignore = "Current blockifier version is not currently in production, no recent tx available for testing"]
fn blockifier_test_recent_tx() {
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

    assert_eq!(actual_fee.0, receipt.actual_fee.amount);
    assert_eq!(
        vm_resources.n_memory_holes,
        receipt.execution_resources.n_memory_holes
    );
    assert_eq!(vm_resources.n_steps, receipt.execution_resources.n_steps);
    assert_eq!(
        vm_resources.builtin_instance_counter,
        receipt.execution_resources.builtin_instance_counter
    );
    assert_eq!(
        inner_calls.len(),
        trace
            .execute_invocation
            .as_ref()
            .unwrap()
            .internal_calls
            .len()
    );
}

#[test_case(
    "0x014640564509873cf9d24a311e1207040c8b60efd38d96caef79855f0b0075d5",
    90006,
    RpcChain::MainNet
    => ignore["old transaction, gas mismatch"]
)]
#[test_case(
    "0x025844447697eb7d5df4d8268b23aef6c11de4087936048278c2559fc35549eb",
    197000,
    RpcChain::MainNet
)]
#[test_case(
    "0x00164bfc80755f62de97ae7c98c9d67c1767259427bcf4ccfcc9683d44d54676",
    197000,
    RpcChain::MainNet
)]
#[test_case(
    "0x05d200ef175ba15d676a68b36f7a7b72c17c17604eda4c1efc2ed5e4973e2c91",
    169928, // real block 169929
    RpcChain::MainNet
)]
#[test_case(
    "0x0528ec457cf8757f3eefdf3f0728ed09feeecc50fd97b1e4c5da94e27e9aa1d6",
    169928, // real block 169929
    RpcChain::MainNet
)]
#[test_case(
    "0x0737677385a30ec4cbf9f6d23e74479926975b74db3d55dc5e46f4f8efee41cf",
    169928, // real block 169929
    RpcChain::MainNet
    => ignore["resource mismatch"]
)]
#[test_case(
    "0x026c17728b9cd08a061b1f17f08034eb70df58c1a96421e73ee6738ad258a94c",
    169928, // real block 169929
    RpcChain::MainNet
)]
#[test_case(
    // review later
    "0x0743092843086fa6d7f4a296a226ee23766b8acf16728aef7195ce5414dc4d84",
    186548, // real block     186549
    RpcChain::MainNet
    => ignore["resource mismatch"]
)]
#[test_case(
    "0x00724fc4a84f489ed032ebccebfc9541eb8dc64b0e76b933ed6fc30cd6000bd1",
    186551, // real block     186552
    RpcChain::MainNet
)]
#[test_case(
    "0x04db9b88e07340d18d53b8b876f28f449f77526224afb372daaf1023c8b08036",
    398051, // real block 398052
    RpcChain::MainNet
)]
#[test_case(
    "0x5a5de1f42f6005f3511ea6099daed9bcbcf9de334ee714e8563977e25f71601",
    281513, // real block 281514
    RpcChain::MainNet
)]
#[test_case(
    "0x26be3e906db66973de1ca5eec1ddb4f30e3087dbdce9560778937071c3d3a83",
    351268, // real block 351269
    RpcChain::MainNet
)]
#[test_case(
    "0x4f552c9430bd21ad300db56c8f4cae45d554a18fac20bf1703f180fac587d7e",
    351225, // real block 351226
    RpcChain::MainNet
)]
// DeployAccount for different account providers:

// OpenZeppelin (v0.7.0)
#[test_case(
    "0x04df8a364233d995c33c7f4666a776bf458631bec2633e932b433a783db410f8",
    422881, // real block 422882
    RpcChain::MainNet
)]
// Argent X (v5.7.0)
#[test_case(
    "0x039683c034f8e67cfb4af6e3109cefb3c170ee15ceacf07ee2d926915c4620e5",
    475945, // real block 475946
    RpcChain::MainNet
)]
fn blockifier_test_case_tx(hash: &str, block_number: u64, chain: RpcChain) {
    let (tx_info, trace, receipt) = execute_tx(hash, chain, BlockNumber(block_number));
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

    let actual_fee = actual_fee.0;
    if receipt.actual_fee.amount != actual_fee {
        let diff = 100 * receipt.actual_fee.amount.abs_diff(actual_fee) / receipt.actual_fee.amount;

        if diff >= 35 {
            assert_eq!(
                actual_fee, receipt.actual_fee.amount,
                "actual_fee mismatch differs from the baseline by more than 35% ({diff}%)",
            );
        }
    }

    assert_eq!(
        vm_resources.n_memory_holes,
        receipt.execution_resources.n_memory_holes
    );
    assert_eq!(vm_resources.n_steps, receipt.execution_resources.n_steps);
    assert_eq!(
        vm_resources.builtin_instance_counter,
        receipt.execution_resources.builtin_instance_counter
    );

    assert_eq!(
        inner_calls.len(),
        trace
            .execute_invocation
            .as_ref()
            .unwrap()
            .internal_calls
            .len()
    );
}

#[test_case(
    "0x00b6d59c19d5178886b4c939656167db0660fe325345138025a3cc4175b21897",
    200303, // real block     200304
    RpcChain::MainNet => ignore["Doesn't revert in newest blockifier version"]
    )]
#[test_case(
    "0x02b28b4846a756e0cec6385d6d13f811e745a88c7e75a3ebc5fead5b4af152a3",
    200302, // real block     200304
    RpcChain::MainNet
    => ignore["broken on both due to a cairo-vm error"]
)]
fn blockifier_test_case_reverted_tx(hash: &str, block_number: u64, chain: RpcChain) {
    let (tx_info, trace, receipt) = execute_tx(hash, chain, BlockNumber(block_number));

    assert_eq!(
        tx_info.revert_error.is_some(),
        trace.execute_invocation.unwrap().revert_reason.is_some()
    );

    let diff =
        100 * receipt.actual_fee.amount.abs_diff(tx_info.actual_fee.0) / receipt.actual_fee.amount;

    if diff >= 5 {
        assert_eq!(
            tx_info.actual_fee.0, receipt.actual_fee.amount,
            "actual_fee mismatch differs from the baseline by more than 5% ({diff}%)",
        );
    }
}

#[test_case(
    // Declare tx
    "0x60506c49e65d84e2cdd0e9142dc43832a0a59cb6a9cbcce1ab4f57c20ba4afb",
    347899, // real block 347900
    RpcChain::MainNet
)]
#[test_case(
    // Declare tx
    "0x1088aa18785779e1e8eef406dc495654ad42a9729b57969ad0dbf2189c40bee",
    271887, // real block 271888
    RpcChain::MainNet
)]
fn blockifier_test_case_declare_tx(hash: &str, block_number: u64, chain: RpcChain) {
    let (tx_info, _trace, receipt) = execute_tx(hash, chain, BlockNumber(block_number));
    let TransactionExecutionInfo {
        execute_call_info,
        actual_fee,
        ..
    } = tx_info;

    assert!(execute_call_info.is_none());

    let actual_fee = actual_fee.0;
    if receipt.actual_fee.amount != actual_fee {
        let diff = 100 * receipt.actual_fee.amount.abs_diff(actual_fee) / receipt.actual_fee.amount;

        if diff >= 35 {
            assert_eq!(
                actual_fee, receipt.actual_fee.amount,
                "actual_fee mismatch differs from the baseline by more than 35% ({diff}%)",
            );
        }
    }
}
