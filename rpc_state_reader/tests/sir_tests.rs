#![cfg(feature = "starknet_in_rust")]

use cairo_vm::Felt252;
use pretty_assertions_sorted::{assert_eq, assert_eq_sorted};
use rpc_state_reader::{
    execute_tx, execute_tx_configurable, execute_tx_without_validate, rpc_state::*,
};
use starknet_api::{
    block::BlockNumber,
    hash::StarkFelt,
    stark_felt,
    transaction::{Transaction as SNTransaction, TransactionHash},
};
use starknet_in_rust::{
    execution::{CallInfo, TransactionExecutionInfo},
    transaction::InvokeFunction,
};
use test_case::test_case;

#[test]
fn test_get_transaction_try_from() {
    let rpc_state = RpcState::new_rpc(RpcChain::MainNet, BlockTag::Latest.into()).unwrap();
    let str_hash = stark_felt!("0x5d200ef175ba15d676a68b36f7a7b72c17c17604eda4c1efc2ed5e4973e2c91");
    let tx_hash = TransactionHash(str_hash);

    let sn_tx = rpc_state.get_transaction(&tx_hash).unwrap();
    match &sn_tx {
        SNTransaction::Invoke(sn_tx) => {
            let tx = InvokeFunction::from_invoke_transaction(
                sn_tx.clone(),
                Felt252::from_bytes_be_slice(tx_hash.0.bytes()),
            )
            .unwrap();
            assert_eq!(tx.hash_value().to_bytes_be().as_slice(), str_hash.bytes())
        }
        _ => unimplemented!(),
    };
}

#[test]
fn test_get_gas_price() {
    let block = BlockValue::Number(BlockNumber(169928));
    let rpc_state = RpcState::new_rpc(RpcChain::MainNet, block).unwrap();

    let price = rpc_state.get_gas_price(169928).unwrap();
    assert_eq!(price.eth_l1_gas_price, 22804578690);
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
fn starknet_in_rust_test_case_tx(hash: &str, block_number: u64, chain: RpcChain) {
    let (tx_info, trace, receipt) = execute_tx(hash, chain, BlockNumber(block_number)).unwrap();

    let TransactionExecutionInfo {
        call_info,
        actual_fee,
        ..
    } = tx_info;
    #[cfg_attr(feature = "cairo-native", allow(unused_variables))]
    let CallInfo {
        execution_resources,
        internal_calls,
        ..
    } = call_info.unwrap();

    // check Cairo VM execution resources
    #[cfg(not(feature = "cairo-native"))]
    assert_eq_sorted!(
        execution_resources.as_ref(),
        Some(&receipt.execution_resources),
        "execution resources mismatch"
    );

    // check amount of internal calls
    assert_eq!(
        internal_calls.len(),
        trace
            .execute_invocation
            .as_ref()
            .unwrap()
            .internal_calls
            .len(),
        "internal calls length mismatch"
    );

    // check actual fee calculation
    if receipt.actual_fee.amount != actual_fee {
        let diff = 100 * receipt.actual_fee.amount.abs_diff(actual_fee) / receipt.actual_fee.amount;

        if diff >= 35 {
            assert_eq!(
                actual_fee, receipt.actual_fee.amount,
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
    let (tx_info, _trace, _receipt) =
        execute_tx(tx_hash, chain, BlockNumber(block_number)).unwrap();

    let events_len = tx_info.get_sorted_events().unwrap().len();

    assert_eq!(expected_amount_of_events, events_len);
}

#[test_case(
    "0x00b6d59c19d5178886b4c939656167db0660fe325345138025a3cc4175b21897",
    200303, // real block     200304
    RpcChain::MainNet => ignore["Old tx"]
)]
#[test_case(
    "0x02b28b4846a756e0cec6385d6d13f811e745a88c7e75a3ebc5fead5b4af152a3",
    200302, // real block     200304
    RpcChain::MainNet
    => ignore["broken on both due to a cairo-vm error"]
)]
// Insufficient fee token balance
#[test_case(
    "0x006978ae71587d4ab1048d7836c2d656222a16976c82c0dc24d3b44316d63cfe",
    440823, // real block     440824
    RpcChain::MainNet
)]
// Insufficient fee token balance
#[test_case(
    "0x03e458ef06c17dd2601013746ae5622d8434348b246a335b20b6543f37aff0f8",
    440849, // real block     440850
    RpcChain::MainNet
)]
fn starknet_in_rust_test_case_reverted_tx(hash: &str, block_number: u64, chain: RpcChain) {
    let (tx_info, trace, receipt) = execute_tx(hash, chain, BlockNumber(block_number)).unwrap();

    assert_eq!(
        tx_info.revert_error.is_some(),
        trace.execute_invocation.unwrap().revert_reason.is_some()
    );

    let diff =
        100 * receipt.actual_fee.amount.abs_diff(tx_info.actual_fee) / receipt.actual_fee.amount;

    if diff >= 35 {
        assert_eq!(
            tx_info.actual_fee, receipt.actual_fee.amount,
            "actual_fee mismatch differs from the baseline by more than 5% ({diff}%)",
        );
    }
}

#[test_case(
    "0x038c307a0a324dc92778820f2c6317f40157c06b12a7e537f7a16b2c015f64e7",
    274333-1,
    RpcChain::MainNet => ignore["Old tx"]
)]
fn test_validate_fee(hash: &str, block_number: u64, chain: RpcChain) {
    let (tx_info, _trace, receipt) = execute_tx(hash, chain, BlockNumber(block_number)).unwrap();
    let (tx_info_without_fee, _trace, _receipt) =
        execute_tx_without_validate(hash, chain, BlockNumber(block_number)).unwrap();

    assert_eq!(tx_info.actual_fee, receipt.actual_fee.amount);
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
    let (tx_info, _trace, receipt) = execute_tx(hash, chain, BlockNumber(block_number)).unwrap();
    let TransactionExecutionInfo {
        call_info,
        actual_fee,
        ..
    } = tx_info;

    assert!(call_info.is_none());

    if receipt.actual_fee.amount != actual_fee {
        let diff = 100 * receipt.actual_fee.amount.abs_diff(actual_fee) / receipt.actual_fee.amount;

        if diff >= 35 {
            assert_eq!(
                actual_fee, receipt.actual_fee.amount,
                "actual_fee mismatch differs from the baseline by more than 5% ({diff}%)",
            );
        }
    }
}

#[test_case(
    "0x0200b493df8310215b188343f227dd1894c9edda597465cb336d25610172c701",
    470061, // real block 470062
    RpcChain::MainNet
)]
fn starknet_in_rust_test_case_tx_skip_nonce_check(hash: &str, block_number: u64, chain: RpcChain) {
    let (tx_info, trace, receipt) =
        execute_tx_configurable(hash, chain, BlockNumber(block_number), false, true).unwrap();

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
        Some(&receipt.execution_resources),
        "execution resources mismatch"
    );

    // check amount of internal calls
    assert_eq!(
        internal_calls.len(),
        trace
            .execute_invocation
            .as_ref()
            .unwrap()
            .internal_calls
            .len(),
        "internal calls length mismatch"
    );

    // check actual fee calculation
    if receipt.actual_fee.amount != actual_fee {
        let diff = 100 * receipt.actual_fee.amount.abs_diff(actual_fee) / receipt.actual_fee.amount;

        if diff >= 35 {
            assert_eq!(
                actual_fee, receipt.actual_fee.amount,
                "actual_fee mismatch differs from the baseline by more than 5% ({diff}%)",
            );
        }
    }
}

#[test_case(
    "0x05ee0cd7be18a4f8a2d6845a9960c0573318393122fe392c5d156eb460beff21",
    422346, // real block 422347
    RpcChain::MainNet
)]
fn starknet_in_rust_check_fee_and_retdata(hash: &str, block_number: u64, chain: RpcChain) {
    let (tx_info, trace, receipt) = execute_tx(hash, chain, BlockNumber(block_number)).unwrap();

    let TransactionExecutionInfo {
        call_info,
        actual_fee,
        ..
    } = tx_info;
    let CallInfo { retdata, .. } = call_info.unwrap();

    // check actual fee calculation
    if receipt.actual_fee.amount != actual_fee {
        let diff = 100 * receipt.actual_fee.amount.abs_diff(actual_fee) / receipt.actual_fee.amount;

        if diff >= 35 {
            assert_eq!(
                actual_fee, receipt.actual_fee.amount,
                "actual_fee mismatch differs from the baseline by more than 5% ({diff}%)",
            );
        }
    }

    let rpc_retdata: Vec<Felt252> = trace
        .execute_invocation
        .unwrap()
        .retdata
        .unwrap()
        .into_iter()
        .map(|sf| Felt252::from_bytes_be_slice(sf.bytes()))
        .collect();

    assert_eq!(retdata, rpc_retdata);
}
