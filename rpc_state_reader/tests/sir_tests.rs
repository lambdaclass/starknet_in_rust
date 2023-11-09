use std::sync::Arc;

use cairo_vm::felt::{felt_str, Felt252};
use pretty_assertions_sorted::{assert_eq, assert_eq_sorted};
use starknet_api::{
    block::BlockNumber,
    core::{ClassHash as SNClassHash, ContractAddress, PatriciaKey},
    hash::{StarkFelt, StarkHash},
    stark_felt,
    state::StorageKey,
    transaction::{Transaction as SNTransaction, TransactionHash, TransactionVersion},
};
use starknet_in_rust::{
    core::{contract_address::compute_casm_class_hash, errors::state_errors::StateError},
    definitions::{
        block_context::{BlockContext, StarknetChainId, StarknetOsConfig},
        constants::{
            DEFAULT_CAIRO_RESOURCE_FEE_WEIGHTS, DEFAULT_CONTRACT_STORAGE_COMMITMENT_TREE_HEIGHT,
            DEFAULT_GLOBAL_STATE_COMMITMENT_TREE_HEIGHT, DEFAULT_INVOKE_TX_MAX_N_STEPS,
            DEFAULT_VALIDATE_MAX_N_STEPS,
        },
    },
    execution::{CallInfo, TransactionExecutionInfo},
    services::api::contract_classes::compiled_class::CompiledClass,
    state::{
        cached_state::{CachedState, ContractClassCache},
        state_api::StateReader,
        state_cache::StorageEntry,
        BlockInfo,
    },
    transaction::{Declare, DeclareV2, DeployAccount, InvokeFunction, L1Handler},
    utils::{Address, ClassHash},
};

use test_case::test_case;

use rpc_state_reader::rpc_state::*;

#[derive(Debug)]
pub struct RpcStateReader(RpcState);

impl StateReader for RpcStateReader {
    fn get_contract_class(&self, class_hash: &ClassHash) -> Result<CompiledClass, StateError> {
        let hash = SNClassHash(StarkHash::new(*class_hash).unwrap());
        Ok(CompiledClass::from(
            self.0.get_contract_class(&hash).unwrap(),
        ))
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
        Ok(*class_hash)
    }
}

#[allow(unused)]
pub fn execute_tx_configurable(
    tx_hash: &str,
    network: RpcChain,
    block_number: BlockNumber,
    skip_validate: bool,
    skip_nonce_check: bool,
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
    let rpc_reader = RpcStateReader(RpcState::new_infura(network, block_number.into()).unwrap());
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
        } = rpc_reader.0.get_block_info().unwrap();

        let block_number = block_number.0;
        let block_timestamp = block_timestamp.0;
        let sequencer_address = Address(Felt252::from_bytes_be(sequencer_address.0.key().bytes()));

        BlockInfo {
            block_number,
            block_timestamp,
            gas_price,
            sequencer_address,
        }
    };

    // Get transaction before giving ownership of the reader
    let tx_hash = TransactionHash(stark_felt!(tx_hash));
    let tx = match rpc_reader.0.get_transaction(&tx_hash).unwrap() {
        SNTransaction::Invoke(tx) => InvokeFunction::from_invoke_transaction(tx, chain_id)
            .unwrap()
            .create_for_simulation(skip_validate, false, false, false, skip_nonce_check),
        SNTransaction::DeployAccount(tx) => {
            DeployAccount::from_sn_api_transaction(tx, chain_id.to_felt())
                .unwrap()
                .create_for_simulation(skip_validate, false, false, false)
        }
        SNTransaction::Declare(tx) => {
            // Fetch the contract_class from the next block (as we don't have it in the previous one)
            let next_block_state_reader = RpcStateReader(
                RpcState::new_infura(network, (block_number.next()).into()).unwrap(),
            );
            let contract_class = next_block_state_reader
                .get_contract_class(tx.class_hash().0.bytes().try_into().unwrap())
                .unwrap();

            if tx.version() != TransactionVersion(2_u8.into()) {
                let contract_class = match contract_class {
                    CompiledClass::Deprecated(cc) => cc.as_ref().clone(),
                    _ => unreachable!(),
                };

                let declare = Declare::new_with_tx_and_class_hash(
                    contract_class,
                    Address(Felt252::from_bytes_be(tx.sender_address().0.key().bytes())),
                    tx.max_fee().0,
                    Felt252::from_bytes_be(tx.version().0.bytes()),
                    tx.signature()
                        .0
                        .iter()
                        .map(|f| Felt252::from_bytes_be(f.bytes()))
                        .collect(),
                    Felt252::from_bytes_be(tx.nonce().0.bytes()),
                    Felt252::from_bytes_be(tx_hash.0.bytes()),
                    tx.class_hash().0.bytes().try_into().unwrap(),
                )
                .unwrap();
                declare.create_for_simulation(skip_validate, false, false, false)
            } else {
                let contract_class = match contract_class {
                    CompiledClass::Casm(cc) => cc.as_ref().clone(),
                    _ => unreachable!(),
                };

                let compiled_class_hash = compute_casm_class_hash(&contract_class).unwrap();

                let declare = DeclareV2::new_with_sierra_class_hash_and_tx_hash(
                    None,
                    Felt252::from_bytes_be(tx.class_hash().0.bytes()),
                    Some(contract_class),
                    compiled_class_hash,
                    Address(Felt252::from_bytes_be(tx.sender_address().0.key().bytes())),
                    tx.max_fee().0,
                    Felt252::from_bytes_be(tx.version().0.bytes()),
                    tx.signature()
                        .0
                        .iter()
                        .map(|f| Felt252::from_bytes_be(f.bytes()))
                        .collect(),
                    Felt252::from_bytes_be(tx.nonce().0.bytes()),
                    Felt252::from_bytes_be(tx_hash.0.bytes()),
                )
                .unwrap();
                declare.create_for_simulation(skip_validate, false, false, false)
            }
        }
        SNTransaction::L1Handler(tx) => L1Handler::from_sn_api_tx(
            tx,
            Felt252::from_bytes_be(tx_hash.0.bytes()),
            Some(Felt252::from(u128::MAX)),
        )
        .unwrap()
        .create_for_simulation(skip_validate, false),
        _ => unimplemented!(),
    };

    let trace = rpc_reader.0.get_transaction_trace(&tx_hash).unwrap();
    let receipt = rpc_reader.0.get_transaction_receipt(&tx_hash).unwrap();

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

pub fn execute_tx(
    tx_hash: &str,
    network: RpcChain,
    block_number: BlockNumber,
) -> (
    TransactionExecutionInfo,
    TransactionTrace,
    RpcTransactionReceipt,
) {
    execute_tx_configurable(tx_hash, network, block_number, false, true)
}

pub fn execute_tx_without_validate(
    tx_hash: &str,
    network: RpcChain,
    block_number: BlockNumber,
) -> (
    TransactionExecutionInfo,
    TransactionTrace,
    RpcTransactionReceipt,
) {
    execute_tx_configurable(tx_hash, network, block_number, true, true)
}

#[test]
fn test_get_transaction_try_from() {
    let rpc_state = RpcState::new_infura(RpcChain::MainNet, BlockTag::Latest.into()).unwrap();
    let str_hash = stark_felt!("0x5d200ef175ba15d676a68b36f7a7b72c17c17604eda4c1efc2ed5e4973e2c91");
    let tx_hash = TransactionHash(str_hash);

    let sn_tx = rpc_state.get_transaction(&tx_hash).unwrap();
    match &sn_tx {
        SNTransaction::Invoke(sn_tx) => {
            let tx =
                InvokeFunction::from_invoke_transaction(sn_tx.clone(), StarknetChainId::MainNet)
                    .unwrap();
            assert_eq!(tx.hash_value().to_be_bytes().as_slice(), str_hash.bytes())
        }
        _ => unimplemented!(),
    };
}

#[test]
fn test_get_gas_price() {
    let block = BlockValue::Number(BlockNumber(169928));
    let rpc_state = RpcState::new_infura(RpcChain::MainNet, block).unwrap();

    let price = rpc_state.get_gas_price(169928).unwrap();
    assert_eq!(price, 22804578690);
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
        // fails in blockifier
        "0x00724fc4a84f489ed032ebccebfc9541eb8dc64b0e76b933ed6fc30cd6000bd1",
        186551, // real block     186552
        RpcChain::MainNet
    )]
#[test_case(
    "0x176a92e8df0128d47f24eebc17174363457a956fa233cc6a7f8561bfbd5023a",
    317092, // real block 317093
    RpcChain::MainNet
)]
#[test_case(
    "0x1cbc74e101a1533082a021ce53235cfd744899b0ff948d1949a64646e0f15c2",
    885298, // real block 885299
    RpcChain::TestNet
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
// DeployAccount for different account providers (as of October 2023):
// All of them were deployed on testnet using starkli
// OpenZeppelin (v0.7.0)
#[test_case(
    "0x0012696c03a0f0301af190288d9824583be813b71882308e4c5d686bf5967ec5",
    889866, // real block 889867
    RpcChain::TestNet
)]
// Braavos (v3.21.10)
#[test_case(
    "0x04dc838fd4ed265ab2ea5fbab08e67b398e3caaedf75c548113c6b2f995fc9db",
    889858, // real block 889859
    RpcChain::TestNet
)]
// Argent X (v5.7.0)
#[test_case(
    "0x01583c47a929f81f6a8c74d31708a7f161603893435d51b6897017fdcdaafee4",
    889897, // real block 889898
    RpcChain::TestNet
)]
#[test_case(
    "0x05dc2a26a65b0fc9e8cb17d8b3e9142abdb2b2d2dd2f3eb275256f23bddfc9f2",
    899787, // real block 899788
    RpcChain::TestNet
)]
fn starknet_in_rust_test_case_tx(hash: &str, block_number: u64, chain: RpcChain) {
    let (tx_info, trace, receipt) = execute_tx(hash, chain, BlockNumber(block_number));

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

    // check Cairo VM execution resources
    assert_eq_sorted!(
        execution_resources.as_ref(),
        Some(
            &trace
                .function_invocation
                .as_ref()
                .unwrap()
                .execution_resources
        ),
        "execution resources mismatch"
    );

    // check amount of internal calls
    assert_eq!(
        internal_calls.len(),
        trace
            .function_invocation
            .as_ref()
            .unwrap()
            .internal_calls
            .len(),
        "internal calls length mismatch"
    );

    // check actual fee calculation
    if receipt.actual_fee != actual_fee {
        let diff = 100 * receipt.actual_fee.abs_diff(actual_fee) / receipt.actual_fee;

        if diff >= 5 {
            assert_eq!(
                actual_fee, receipt.actual_fee,
                "actual_fee mismatch differs from the baseline by more than 5% ({diff}%)",
            );
        }
    }
}

#[test_case(
    "0x05b4665a81d89d00e529d2e298fce6606750c4f67faf43aafc893c0fc0f9d425",
    RpcChain::MainNet,
    222090,
    4
)]
#[test_case(
    "0x01e91fa12be4424264c8cad29f481a67d5d8e23f7abf94add734d64b91c90021",
    RpcChain::MainNet,
    219797,
    7
)]
#[test_case(
    "0x03ec45f8369513b0f48db25f2cf18c70c50e7d3119505ab15e39ae4ca2eb06cf",
    RpcChain::MainNet,
    219764,
    7
)]
#[test_case(
    "0x00164bfc80755f62de97ae7c98c9d67c1767259427bcf4ccfcc9683d44d54676",
    RpcChain::MainNet,
    197000,
    3
)]
fn test_sorted_events(
    tx_hash: &str,
    chain: RpcChain,
    block_number: u64,
    expected_amount_of_events: usize,
) {
    let (tx_info, _trace, _receipt) = execute_tx(tx_hash, chain, BlockNumber(block_number));

    let events_len = tx_info.get_sorted_events().unwrap().len();

    assert_eq!(expected_amount_of_events, events_len);
}

#[test_case(
    "0x00b6d59c19d5178886b4c939656167db0660fe325345138025a3cc4175b21897",
    200303, // real block     200304
    RpcChain::MainNet
)]
#[test_case(
    "0x02b28b4846a756e0cec6385d6d13f811e745a88c7e75a3ebc5fead5b4af152a3",
    200302, // real block     200304
    RpcChain::MainNet
    => ignore["broken on both due to a cairo-vm error"]
)]
fn starknet_in_rust_test_case_reverted_tx(hash: &str, block_number: u64, chain: RpcChain) {
    let (tx_info, trace, receipt) = execute_tx(hash, chain, BlockNumber(block_number));

    assert_eq!(tx_info.revert_error.is_some(), trace.revert_error.is_some());

    let diff = 100 * receipt.actual_fee.abs_diff(tx_info.actual_fee) / receipt.actual_fee;

    if diff >= 5 {
        assert_eq!(
            tx_info.actual_fee, receipt.actual_fee,
            "actual_fee mismatch differs from the baseline by more than 5% ({diff}%)",
        );
    }
}

#[test_case(
    "0x038c307a0a324dc92778820f2c6317f40157c06b12a7e537f7a16b2c015f64e7",
    274333-1,
    RpcChain::MainNet
)]
fn test_validate_fee(hash: &str, block_number: u64, chain: RpcChain) {
    let (tx_info, _trace, receipt) = execute_tx(hash, chain, BlockNumber(block_number));
    let (tx_info_without_fee, _trace, _receipt) =
        execute_tx_without_validate(hash, chain, BlockNumber(block_number));

    assert_eq!(tx_info.actual_fee, receipt.actual_fee);
    assert!(tx_info_without_fee.actual_fee < tx_info.actual_fee);
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
fn starknet_in_rust_test_case_declare_tx(hash: &str, block_number: u64, chain: RpcChain) {
    let (tx_info, _trace, receipt) = execute_tx(hash, chain, BlockNumber(block_number));
    let TransactionExecutionInfo {
        call_info,
        actual_fee,
        ..
    } = tx_info;

    assert!(call_info.is_none());

    let actual_fee = actual_fee;
    if receipt.actual_fee != actual_fee {
        let diff = 100 * receipt.actual_fee.abs_diff(actual_fee) / receipt.actual_fee;

        if diff >= 5 {
            assert_eq!(
                actual_fee, receipt.actual_fee,
                "actual_fee mismatch differs from the baseline by more than 5% ({diff}%)",
            );
        }
    }
}
