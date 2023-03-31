#![deny(warnings)]
#![forbid(unsafe_code)]

use business_logic::execution::objects::TransactionExecutionInfo;
use business_logic::state::{cached_state::CachedState, state_api::StateReader};
use business_logic::transaction::{error::TransactionError, transactions::Transaction};
use definitions::general_config::StarknetGeneralConfig;
use felt::Felt;

#[cfg(test)]
#[macro_use]
extern crate assert_matches;

pub mod business_logic;
pub mod core;
pub mod definitions;
pub mod hash_utils;
pub mod parser_errors;
pub mod public;
pub mod serde_structs;
pub mod services;
pub mod starknet_runner;
pub mod starknet_storage;
pub mod starkware_utils;
pub mod testing;
pub mod utils;

type TransactionResult<T> = Result<T, TransactionError>;

pub struct SimulationFlags;

pub struct Starknet;

impl Starknet {
    pub fn call_contract<T>(
        &self,
        state: &mut CachedState<T>,
        tx: Transaction,
        config: &StarknetGeneralConfig,
    ) -> TransactionResult<Vec<Felt>>
    where
        T: StateReader + Clone + Default,
    {
        let mut state_copy = state.clone();
        tx.execute(&mut state_copy, config)
            .and_then(|tx_exec| {
                tx_exec
                    .call_info
                    .ok_or(TransactionError::StarknetError(
                        "Empty CallInfo.".to_string(),
                    ))
                    .map(|r| r.retdata)
            })
            .map_err(Into::into)
    }

    pub fn estimate_fee<T>(
        &self,
        state: &CachedState<T>,
        tx: Transaction,
        config: &StarknetGeneralConfig,
    ) -> TransactionResult<u64>
    where
        T: StateReader + Clone + Default,
    {
        let mut state_copy = state.clone();
        // TODO: check if the estimate_fee is the actual_fee.
        tx.execute(&mut state_copy, config)
            .map(|tx_exec| tx_exec.actual_fee)
            .map_err(Into::into)
    }

    pub fn execute_tx<T>(
        &self,
        state: &mut CachedState<T>,
        tx: Transaction,
        config: &StarknetGeneralConfig,
    ) -> TransactionResult<TransactionExecutionInfo>
    where
        T: StateReader + Clone + Default,
    {
        tx.execute(state, config).map_err(Into::into)
    }

    pub fn simulate_tx<T>(
        &self,
        state: &CachedState<T>,
        tx: Transaction,
        config: &StarknetGeneralConfig,
        _options: Option<SimulationFlags>,
    ) -> TransactionResult<(TransactionExecutionInfo, u64)>
    where
        T: StateReader + Clone + Default,
    {
        let mut state_copy = state.clone();
        // TODO: check if the estimate_fee is the actual_fee.
        tx.execute(&mut state_copy, config)
            .map(|tx_exec| (tx_exec.clone(), tx_exec.actual_fee))
            .map_err(Into::into)
    }
}

#[cfg(test)]
mod test {
    use std::path::PathBuf;

    use crate::{
        business_logic::{
            execution::objects::TransactionExecutionInfo,
            fact_state::in_memory_state_reader::InMemoryStateReader,
            state::cached_state::CachedState,
            transaction::{objects::internal_declare::InternalDeclare, transactions::Transaction},
        },
        core::contract_address::starknet_contract_address::compute_class_hash,
        definitions::general_config::{StarknetChainId, StarknetGeneralConfig},
        services::api::contract_class::ContractClass,
        utils::{felt_to_hash, Address},
        Starknet,
    };
    use felt::{felt_str, Felt};
    use lazy_static::lazy_static;

    lazy_static! {
        // include_str! doesn't seem to work in CI
        static ref CONTRACT_CLASS: ContractClass = ContractClass::try_from(PathBuf::from(
            "starknet_programs/account_without_validation.json",
        ))
        .unwrap();
        static ref CLASS_HASH: [u8; 32] = felt_to_hash(&compute_class_hash(
            &CONTRACT_CLASS
        ).unwrap());
        static ref CONTRACT_ADDRESS: Address = Address(felt_str!(
            "3577223136242220508961486249701638158054969090851914040041358274796489907314"
        ));
        static ref SIGNATURE: Vec<Felt> = vec![
            felt_str!("3233776396904427614006684968846859029149676045084089832563834729503047027074"),
            felt_str!("707039245213420890976709143988743108543645298941971188668773816813012281203"),
        ];
    }

    #[test]
    fn simulate_tx_doesnt_change_the_state() {
        let cached_state: CachedState<InMemoryStateReader> = CachedState::default();
        let starknet = Starknet;
        let class = CONTRACT_CLASS.clone();
        let address = CONTRACT_ADDRESS.clone();
        let internal_declare = InternalDeclare::new(
            class,
            StarknetChainId::TestNet.to_felt(),
            address,
            0,
            0,
            vec![],
            0.into(),
        )
        .unwrap();
        let declare_tx = Transaction::Declare(internal_declare);
        let config = StarknetGeneralConfig::default();
        let (tx_exec_info, fee) = starknet
            .simulate_tx(&cached_state, declare_tx, &config, None)
            .unwrap();

        assert_eq!(0, fee);
        assert_eq!(TransactionExecutionInfo::default(), tx_exec_info);
    }

    #[test]
    fn estimate_fee_doesnt_change_the_state() {}

    #[test]
    fn call_contract_doesnt_change_the_state() {}

    #[test]
    fn executing_a_declare_tx_changes_the_state_correctly() {
        let mut cached_state: CachedState<InMemoryStateReader> = CachedState::default();
        let starknet = Starknet;
        let class = CONTRACT_CLASS.clone();
        let address = CONTRACT_ADDRESS.clone();
        let internal_declare = InternalDeclare::new(
            class,
            StarknetChainId::TestNet.to_felt(),
            address,
            0,
            0,
            vec![],
            0.into(),
        )
        .unwrap();
        let declare_tx = Transaction::Declare(internal_declare);
        let config = StarknetGeneralConfig::default();
        let tx_exec_info = starknet
            .execute_tx(&mut cached_state, declare_tx, &config)
            .unwrap();

        assert_eq!(TransactionExecutionInfo::default(), tx_exec_info)
    }
}
