#![cfg(feature = "starknet_in_rust")]

use pretty_assertions_sorted::{assert_eq, assert_eq_sorted};
use starknet_api::{
    block::BlockNumber,
    hash::StarkFelt,
    stark_felt,
    transaction::{Transaction as SNTransaction, TransactionHash},
};
use starknet_in_rust::{
    definitions::block_context::StarknetChainId,
    execution::{CallInfo, TransactionExecutionInfo},
    transaction::InvokeFunction,
};

use test_case::test_case;

use rpc_state_reader::{execute_tx, execute_tx_without_validate, rpc_state::*};

#[test]
fn test_get_transaction_try_from() {
    let rpc_state = RpcState::new_infura(RpcChain::MainNet, BlockTag::Latest.into());
    let str_hash = stark_felt!("0x5d200ef175ba15d676a68b36f7a7b72c17c17604eda4c1efc2ed5e4973e2c91");
    let tx_hash = TransactionHash(str_hash);

    let sn_tx = rpc_state.get_transaction(&tx_hash);
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
    let rpc_state = RpcState::new_infura(RpcChain::MainNet, block);

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
        execution_resources,
        trace
            .function_invocation
            .as_ref()
            .unwrap()
            .execution_resources,
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
