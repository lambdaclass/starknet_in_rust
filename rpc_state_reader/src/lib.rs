pub mod rpc_state;
pub mod rpc_state_errors;
pub mod utils;

// only export the sir_state_reader module when the starknet_in_rust feature
// is enabled.
#[cfg(feature = "starknet_in_rust")]
mod sir_state_reader;
#[cfg(feature = "starknet_in_rust")]
pub use sir_state_reader::{
    execute_tx, execute_tx_configurable, execute_tx_configurable_with_state,
    execute_tx_without_validate, get_transaction_hashes, RpcStateReader,
};

#[cfg(test)]
mod tests {
    use cairo_vm::Felt252;
    use pretty_assertions_sorted::{assert_eq, assert_eq_sorted};
    use starknet_api::{
        class_hash,
        core::{ClassHash, ContractAddress, PatriciaKey},
        hash::{StarkFelt, StarkHash},
        patricia_key, stark_felt,
        state::StorageKey,
        transaction::{Transaction as SNTransaction, TransactionHash},
    };
    use starknet_in_rust::transaction::InvokeFunction;

    use crate::rpc_state::*;

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
        let rpc_state = RpcState::new_rpc(RpcChain::MainNet, BlockTag::Latest.into()).unwrap();

        let class_hash =
            class_hash!("0298e56befa6d1446b86ed5b900a9ba51fd2faa683cd6f50e8f833c0fb847216");
        // This belongs to
        // https://starkscan.co/class/0x0298e56befa6d1446b86ed5b900a9ba51fd2faa683cd6f50e8f833c0fb847216
        // which is cairo1.0

        rpc_state.get_contract_class(&class_hash);
    }

    #[test]
    fn test_get_contract_class_cairo0() {
        let rpc_state = RpcState::new_rpc(RpcChain::MainNet, BlockTag::Latest.into()).unwrap();

        let class_hash =
            class_hash!("025ec026985a3bf9d0cc1fe17326b245dfdc3ff89b8fde106542a3ea56c5a918");
        rpc_state.get_contract_class(&class_hash);
    }

    #[test]
    fn test_get_class_hash_at() {
        let rpc_state = RpcState::new_rpc(RpcChain::MainNet, BlockTag::Latest.into()).unwrap();
        let address =
            contract_address!("00b081f7ba1efc6fe98770b09a827ae373ef2baa6116b3d2a0bf5154136573a9");

        assert_eq!(
            rpc_state.get_class_hash_at(&address),
            class_hash!("025ec026985a3bf9d0cc1fe17326b245dfdc3ff89b8fde106542a3ea56c5a918")
        );
    }

    #[test]
    fn test_get_nonce_at() {
        let rpc_state = RpcState::new_rpc(RpcChain::TestNet, BlockTag::Latest.into()).unwrap();
        // Contract deployed by xqft which will not be used again, so nonce changes will not break
        // this test.
        let address =
            contract_address!("07185f2a350edcc7ea072888edb4507247de23e710cbd56084c356d265626bea");
        assert_eq!(rpc_state.get_nonce_at(&address), stark_felt!("0x0"));
    }

    #[test]
    fn test_get_storage_at() {
        let rpc_state = RpcState::new_rpc(RpcChain::MainNet, BlockTag::Latest.into()).unwrap();
        let address =
            contract_address!("00b081f7ba1efc6fe98770b09a827ae373ef2baa6116b3d2a0bf5154136573a9");
        let key = StorageKey(patricia_key!(0u128));

        assert_eq_sorted!(rpc_state.get_storage_at(&address, &key), stark_felt!("0x0"));
    }

    #[test]
    fn test_get_transaction() {
        let rpc_state = RpcState::new_rpc(RpcChain::MainNet, BlockTag::Latest.into()).unwrap();
        let tx_hash = TransactionHash(stark_felt!(
            "06da92cfbdceac5e5e94a1f40772d6c79d34f011815606742658559ec77b6955"
        ));

        assert!(rpc_state.get_transaction(&tx_hash).is_ok());
    }

    #[test]
    fn test_try_from_invoke() {
        let rpc_state = RpcState::new_rpc(RpcChain::MainNet, BlockTag::Latest.into()).unwrap();
        let tx_hash = TransactionHash(stark_felt!(
            "06da92cfbdceac5e5e94a1f40772d6c79d34f011815606742658559ec77b6955"
        ));

        let tx = rpc_state.get_transaction(&tx_hash).unwrap();
        match tx {
            SNTransaction::Invoke(tx) => InvokeFunction::from_invoke_transaction(
                tx,
                Felt252::from_bytes_be_slice(tx_hash.0.bytes()),
            ),
            _ => unreachable!(),
        }
        .unwrap();
    }

    #[test]
    fn test_get_block_info() {
        let rpc_state = RpcState::new_rpc(RpcChain::MainNet, BlockTag::Latest.into()).unwrap();

        assert!(rpc_state.get_block_info().is_ok());
    }

    // Tested with the following query to the Feeder Gateway API:
    // https://alpha-mainnet.starknet.io/feeder_gateway/get_transaction_trace?transactionHash=0x035673e42bd485ae699c538d8502f730d1137545b22a64c094ecdaf86c59e592
    #[test]
    fn test_get_transaction_trace() {
        let rpc_state = RpcState::new_rpc(RpcChain::MainNet, BlockTag::Latest.into()).unwrap();

        let tx_hash = TransactionHash(stark_felt!(
            "0x035673e42bd485ae699c538d8502f730d1137545b22a64c094ecdaf86c59e592"
        ));

        let tx_trace = rpc_state.get_transaction_trace(&tx_hash).unwrap();

        assert_eq!(
            tx_trace.validate_invocation.as_ref().unwrap().calldata,
            Some(vec![
                stark_felt!("1"),
                stark_felt!("0x45dc42889b6292c540de9def0341364bd60c2d8ccced459fac8b1bfc24fa1f5"),
                stark_felt!("0xb758361d5e84380ef1e632f89d8e76a8677dbc3f4b93a4f9d75d2a6048f312"),
                stark_felt!("0"),
                stark_felt!("0xa"),
                stark_felt!("0xa"),
                stark_felt!("0x3fed4"),
                stark_felt!("0"),
                stark_felt!("0xdf6aedb"),
                stark_felt!("0"),
                stark_felt!("0"),
                stark_felt!("0"),
                stark_felt!("0x47c5f10d564f1623566b940a61fe54754bfff996f7536901ec969b12874f87f"),
                stark_felt!("2"),
                stark_felt!("0x72034953cd93dc8618123b4802003bae1f469b526bc18355250080c0f93dc17"),
                stark_felt!("0x5f2ac628fa43d58fb8a6b7a2739de5c1edb550cb13cdcec5bc99f00135066a7"),
            ])
        );
        assert_eq!(
            tx_trace.validate_invocation.as_ref().unwrap().retdata,
            Some(vec![])
        );
        assert_eq!(
            tx_trace
                .validate_invocation
                .as_ref()
                .unwrap()
                .internal_calls
                .len(),
            1
        );

        assert_eq!(
            tx_trace.execute_invocation.as_ref().unwrap().calldata,
            Some(vec![
                stark_felt!("0x1"),
                stark_felt!("0x45dc42889b6292c540de9def0341364bd60c2d8ccced459fac8b1bfc24fa1f5"),
                stark_felt!("0xb758361d5e84380ef1e632f89d8e76a8677dbc3f4b93a4f9d75d2a6048f312"),
                stark_felt!("0x0"),
                stark_felt!("0xa"),
                stark_felt!("0xa"),
                stark_felt!("0x3fed4"),
                stark_felt!("0x0"),
                stark_felt!("0xdf6aedb"),
                stark_felt!("0x0"),
                stark_felt!("0x0"),
                stark_felt!("0x0"),
                stark_felt!("0x47c5f10d564f1623566b940a61fe54754bfff996f7536901ec969b12874f87f"),
                stark_felt!("0x2"),
                stark_felt!("0x72034953cd93dc8618123b4802003bae1f469b526bc18355250080c0f93dc17"),
                stark_felt!("0x5f2ac628fa43d58fb8a6b7a2739de5c1edb550cb13cdcec5bc99f00135066a7")
            ])
        );
        assert_eq!(
            tx_trace.execute_invocation.as_ref().unwrap().retdata,
            Some(vec![0u128.into()])
        );
        assert_eq!(
            tx_trace
                .execute_invocation
                .as_ref()
                .unwrap()
                .internal_calls
                .len(),
            1
        );
        assert_eq!(
            tx_trace.execute_invocation.as_ref().unwrap().internal_calls[0]
                .internal_calls
                .len(),
            1
        );
        assert_eq!(
            tx_trace.execute_invocation.as_ref().unwrap().internal_calls[0].internal_calls[0]
                .internal_calls
                .len(),
            0
        );

        assert_eq!(
            tx_trace.fee_transfer_invocation.as_ref().unwrap().calldata,
            Some(vec![
                stark_felt!("0x1176a1bd84444c89232ec27754698e5d2e7e1a7f1539f12027f28b23ec9f3d8"),
                stark_felt!("0x2439e47667460"),
                stark_felt!("0"),
            ])
        );
        assert_eq!(
            tx_trace.fee_transfer_invocation.as_ref().unwrap().retdata,
            Some(vec![1u128.into()])
        );
        assert_eq!(
            tx_trace
                .fee_transfer_invocation
                .as_ref()
                .unwrap()
                .internal_calls
                .len(),
            1
        );
    }

    #[test]
    fn test_get_transaction_receipt() {
        let rpc_state = RpcState::new_rpc(RpcChain::MainNet, BlockTag::Latest.into()).unwrap();
        let tx_hash = TransactionHash(stark_felt!(
            "06da92cfbdceac5e5e94a1f40772d6c79d34f011815606742658559ec77b6955"
        ));

        assert!(rpc_state.get_transaction_receipt(&tx_hash).is_ok());
    }
}
