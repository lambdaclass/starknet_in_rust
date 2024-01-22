use crate::{
    definitions::block_context::BlockContext,
    definitions::{
        block_context::FeeType,
        constants::{QUERY_VERSION_0, QUERY_VERSION_1, QUERY_VERSION_2},
    },
    execution::TransactionExecutionInfo,
    state::{
        cached_state::CachedState, contract_class_cache::ContractClassCache, state_api::StateReader,
    },
    utils::Address,
};
pub use declare::Declare;
pub use declare_v2::DeclareV2;
pub use deploy::Deploy;
pub use deploy_account::DeployAccount;
use error::TransactionError;
pub use invoke_function::InvokeFunction;
pub use l1_handler::L1Handler;

pub mod declare;
pub mod declare_v2;
pub mod deploy;
pub mod deploy_account;
pub mod error;
pub mod fee;
pub mod invoke_function;
pub mod l1_handler;

use cairo_vm::Felt252;
use num_traits::Zero;

#[cfg(feature = "cairo-native")]
use {
    crate::utils::ClassHash,
    cairo_native::cache::ProgramCache,
    std::{cell::RefCell, rc::Rc},
};

/// Represents a transaction inside the starknet network.
/// The transaction are actions that may modified the state of the network.
/// it can be one of:
/// - Declare
/// - DeclareV2
/// - Deploy
/// - DeployAccount
/// - InvokeFunction
/// - L1Handler
pub enum Transaction {
    /// A declare transaction.
    Declare(Declare),
    /// A declare transaction.
    DeclareV2(Box<DeclareV2>),
    /// A deploy transaction.
    Deploy(Deploy),
    /// A deploy account transaction.
    DeployAccount(DeployAccount),
    /// An invoke transaction.
    InvokeFunction(InvokeFunction),
    /// An L1 handler transaction.
    L1Handler(L1Handler),
}

impl Transaction {
    /// returns the contract address of the transaction.
    pub fn contract_address(&self) -> Address {
        match self {
            Transaction::Deploy(tx) => tx.contract_address.clone(),
            Transaction::InvokeFunction(tx) => tx.contract_address().clone(),
            Transaction::Declare(tx) => tx.sender_address.clone(),
            Transaction::DeclareV2(tx) => tx.sender_address.clone(),
            Transaction::DeployAccount(tx) => tx.contract_address().clone(),
            Transaction::L1Handler(tx) => tx.contract_address().clone(),
        }
    }

    /// execute the transaction in cairo-vm and returns a TransactionExecutionInfo structure.
    ///## Parameters:
    ///- state: a structure that implements State and StateReader traits.
    ///- block_context: The block context of the transaction that is about to be executed.
    ///- remaining_gas: The gas supplied to execute the transaction.
    pub fn execute<S: StateReader, C: ContractClassCache>(
        &self,
        state: &mut CachedState<S, C>,
        block_context: &BlockContext,
        remaining_gas: u128,
        #[cfg(feature = "cairo-native")] program_cache: Option<
            Rc<RefCell<ProgramCache<'_, ClassHash>>>,
        >,
    ) -> Result<TransactionExecutionInfo, TransactionError> {
        match self {
            Transaction::Declare(tx) => tx.execute(
                state,
                block_context,
                #[cfg(feature = "cairo-native")]
                program_cache,
            ),
            Transaction::DeclareV2(tx) => tx.execute(
                state,
                block_context,
                #[cfg(feature = "cairo-native")]
                program_cache,
            ),
            Transaction::Deploy(tx) => tx.execute(
                state,
                block_context,
                #[cfg(feature = "cairo-native")]
                program_cache,
            ),
            Transaction::DeployAccount(tx) => tx.execute(
                state,
                block_context,
                #[cfg(feature = "cairo-native")]
                program_cache,
            ),
            Transaction::InvokeFunction(tx) => tx.execute(
                state,
                block_context,
                remaining_gas,
                #[cfg(feature = "cairo-native")]
                program_cache,
            ),
            Transaction::L1Handler(tx) => tx.execute(
                state,
                block_context,
                remaining_gas,
                #[cfg(feature = "cairo-native")]
                program_cache,
            ),
        }
    }

    /// It creates a new transaction structure modificating the skip flags. It is meant to be used only to run a simulation
    ///## Parameters:
    ///- skip_validate: the transaction will not be verified.
    ///- skip_execute: the transaction will not be executed in the cairo vm.
    ///- skip_fee_transfer: the transaction will not pay the fee.
    pub fn create_for_simulation(
        &self,
        skip_validate: bool,
        skip_execute: bool,
        skip_fee_transfer: bool,
        ignore_max_fee: bool,
        skip_nonce_check: bool,
    ) -> Self {
        match self {
            Transaction::Declare(tx) => tx.create_for_simulation(
                skip_validate,
                skip_execute,
                skip_fee_transfer,
                ignore_max_fee,
                skip_nonce_check,
            ),
            Transaction::DeclareV2(tx) => tx.create_for_simulation(
                skip_validate,
                skip_execute,
                skip_fee_transfer,
                ignore_max_fee,
                skip_nonce_check,
            ),
            Transaction::Deploy(tx) => {
                tx.create_for_simulation(skip_validate, skip_execute, skip_fee_transfer)
            }
            Transaction::DeployAccount(tx) => tx.create_for_simulation(
                skip_validate,
                skip_execute,
                skip_fee_transfer,
                ignore_max_fee,
                skip_nonce_check,
            ),
            Transaction::InvokeFunction(tx) => tx.create_for_simulation(
                skip_validate,
                skip_execute,
                skip_fee_transfer,
                ignore_max_fee,
                skip_nonce_check,
            ),
            Transaction::L1Handler(tx) => tx.create_for_simulation(skip_validate, skip_execute),
        }
    }
}

// Parses query tx versions into their normal counterpart
// This is used to execute old transactions an may be removed in the future as its not part of the current standard implementation
fn get_tx_version(version: Felt252) -> Felt252 {
    match version {
        version if version == *QUERY_VERSION_0 => Felt252::ZERO,
        version if version == *QUERY_VERSION_1 => Felt252::ONE,
        version if version == *QUERY_VERSION_2 => 2.into(),
        version => version,
    }
}

/// Contains the account information of the transaction (outermost call).
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AccountTransactionContext {
    //Current(CurrentAccountTransactionContext),
    Deprecated(DeprecatedAccountTransactionContext),
}

impl Default for AccountTransactionContext {
    fn default() -> Self {
        Self::Deprecated(Default::default())
    }
}

// #[derive(Clone, Debug, Eq, PartialEq)]
// pub struct CurrentAccountTransactionContext {
//     pub common_fields: CommonAccountFields,
//     pub resource_bounds: ResourceBoundsMapping,
//     pub tip: Tip,
//     pub nonce_data_availability_mode: DataAvailabilityMode,
//     pub fee_data_availability_mode: DataAvailabilityMode,
//     pub paymaster_data: PaymasterData,
//     pub account_deployment_data: AccountDeploymentData,
// }

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct DeprecatedAccountTransactionContext {
    pub common_fields: CommonAccountFields,
    pub max_fee: u128,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct CommonAccountFields {
    pub transaction_hash: Felt252,
    pub version: Felt252,
    pub signature: Vec<Felt252>,
    pub nonce: Felt252,
    pub sender_address: Address,
    pub only_query: bool,
}

impl AccountTransactionContext {
    pub fn signature(&self) -> &Vec<Felt252> {
        match self {
            AccountTransactionContext::Deprecated(datc) => &datc.common_fields.signature,
        }
    }

    pub fn enforce_fee(&self) -> Result<bool, TransactionError> {
        match self {
            AccountTransactionContext::Deprecated(datc) => Ok(datc.max_fee.is_zero()),
        }
    }

    pub fn version(&self) -> Felt252 {
        match self {
            AccountTransactionContext::Deprecated(datc) => datc.common_fields.version,
        }
    }

    pub fn nonce(&self) -> Felt252 {
        match self {
            AccountTransactionContext::Deprecated(datc) => datc.common_fields.nonce,
        }
    }

    pub fn only_query(&self) -> bool {
        match self {
            AccountTransactionContext::Deprecated(datc) => datc.common_fields.only_query,
        }
    }

    pub fn fee_type(&self) -> FeeType {
        if self.version() < Felt252::THREE {
            FeeType::Eth
        } else {
            FeeType::Strk
        }
    }

    pub fn max_fee(&self) -> u128 {
        match self {
            AccountTransactionContext::Deprecated(datc) => datc.max_fee,
        }
    }

    pub fn sender_address(&self) -> Address {
        match self {
            AccountTransactionContext::Deprecated(datc) => datc.common_fields.sender_address,
        }
    }

    pub fn transaction_hash(&self) -> Felt252 {
        match self {
            AccountTransactionContext::Deprecated(datc) => datc.common_fields.transaction_hash,
        }
    }
}
