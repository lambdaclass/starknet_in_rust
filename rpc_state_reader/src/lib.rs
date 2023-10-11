pub mod rpc_state;
pub mod utils;

// only export the sir_state_reader module when the starknet_in_rust feature
// is enabled.
#[cfg(feature = "starknet_in_rust")]
mod sir_state_reader;
#[cfg(feature = "starknet_in_rust")]
pub use sir_state_reader::{
    execute_tx, execute_tx_configurable, execute_tx_without_validate, RpcStateReader,
};

#[cfg(test)]
mod tests {
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
