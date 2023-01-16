use std::{
    collections::{HashMap, HashSet},
    default,
    ops::{BitAnd, BitOr, Sub},
};

use cairo_rs::{
    types::relocatable::{MaybeRelocatable, Relocatable},
    vm::{runners::cairo_runner::ExecutionResources, vm_core::VirtualMachine},
};
use felt::{Felt, NewFelt};
use num_traits::{ToPrimitive, Zero};

use crate::{
    business_logic::state::state_api::State,
    core::{
        errors::syscall_handler_errors::SyscallHandlerError, syscalls::syscall_request::FromPtr,
    },
    definitions::general_config::StarknetChainId,
    utils::{get_big_int, get_integer, get_relocatable},
};

use super::execution_errors::ExecutionError;

#[derive(Debug, PartialEq, Default)]
pub(crate) enum CallType {
    #[default]
    Call,
    Delegate,
}

#[derive(Debug, PartialEq, Default)]
pub(crate) enum EntryPointType {
    #[default]
    External,
    L1Handler,
    Constructor,
}

#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub(crate) struct OrderedEvent {
    #[allow(unused)] // TODO: remove once used
    order: u64,
    #[allow(unused)] // TODO: remove once used
    keys: Vec<Felt>,
    #[allow(unused)] // TODO: remove once used
    data: Vec<Felt>,
}

impl OrderedEvent {
    pub fn new(order: u64, keys: Vec<Felt>, data: Vec<Felt>) -> Self {
        OrderedEvent { order, keys, data }
    }
}

#[derive(Clone)]
pub(crate) struct TransactionExecutionContext {
    pub(crate) n_emitted_events: u64,
    pub(crate) version: usize,
    pub(crate) account_contract_address: Felt,
    pub(crate) max_fee: u64,
    pub(crate) transaction_hash: Felt,
    pub(crate) signature: Vec<Felt>,
    pub(crate) nonce: Felt,
    pub(crate) n_sent_messages: usize,
}

impl TransactionExecutionContext {
    pub fn new() -> Self {
        TransactionExecutionContext {
            n_emitted_events: 0,
            account_contract_address: Felt::zero(),
            max_fee: 0,
            nonce: Felt::zero(),
            signature: Vec::new(),
            transaction_hash: Felt::zero(),
            version: 0,
            n_sent_messages: 0,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub(crate) struct OrderedL2ToL1Message {
    pub(crate) order: usize,
    pub(crate) to_address: u64,
    pub(crate) payload: Vec<Felt>,
}

impl OrderedL2ToL1Message {
    pub fn new(order: usize, to_address: u64, payload: Vec<Felt>) -> Self {
        OrderedL2ToL1Message {
            order,
            to_address,
            payload,
        }
    }
}

#[derive(Debug, PartialEq)]
pub struct L2toL1MessageInfo {
    pub(crate) from_address: u64,
    pub(crate) to_address: u64,
    pub(crate) payload: Vec<Felt>,
}

impl L2toL1MessageInfo {
    pub(crate) fn new(
        message_content: OrderedL2ToL1Message,
        sending_contract_address: u64,
    ) -> Self {
        L2toL1MessageInfo {
            from_address: sending_contract_address,
            to_address: message_content.to_address,
            payload: message_content.payload,
        }
    }
}

#[allow(unused)] // TODO: Remove once used.
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct TxInfoStruct {
    pub(crate) version: usize,
    pub(crate) account_contract_address: Felt,
    pub(crate) max_fee: u64,
    pub(crate) signature_len: usize,
    pub(crate) signature: Relocatable,
    pub(crate) transaction_hash: Felt,
    pub(crate) chain_id: Felt,
    pub(crate) nonce: Felt,
}

impl TxInfoStruct {
    pub(crate) fn new(
        tx: TransactionExecutionContext,
        signature: Relocatable,
        chain_id: StarknetChainId,
    ) -> TxInfoStruct {
        TxInfoStruct {
            version: tx.version,
            account_contract_address: tx.account_contract_address,
            max_fee: tx.max_fee,
            signature_len: tx.signature.len(),
            signature,
            transaction_hash: tx.transaction_hash,
            chain_id: chain_id.to_felt(),
            nonce: tx.nonce,
        }
    }

    pub(crate) fn to_vec(&self) -> Vec<MaybeRelocatable> {
        vec![
            MaybeRelocatable::from(Felt::new(self.version)),
            MaybeRelocatable::from(&self.account_contract_address),
            MaybeRelocatable::from(Felt::new(self.max_fee)),
            MaybeRelocatable::from(Felt::new(self.signature_len)),
            MaybeRelocatable::from(&self.signature),
            MaybeRelocatable::from(&self.transaction_hash),
            MaybeRelocatable::from(&self.chain_id),
            MaybeRelocatable::from(&self.nonce),
        ]
    }

    pub(crate) fn from_ptr(
        vm: &VirtualMachine,
        tx_info_ptr: Relocatable,
    ) -> Result<TxInfoStruct, SyscallHandlerError> {
        let version = get_integer(vm, &tx_info_ptr)?;

        let account_contract_address = get_big_int(vm, &(&tx_info_ptr + 1))?;
        let max_fee = get_big_int(vm, &(&tx_info_ptr + 2))?
            .to_u64()
            .ok_or(SyscallHandlerError::FeltToU64Fail)?;
        let signature_len = get_integer(vm, &(&tx_info_ptr + 3))?;
        let signature = get_relocatable(vm, &(&tx_info_ptr + 4))?;
        let transaction_hash = get_big_int(vm, &(&tx_info_ptr + 5))?;
        let chain_id = get_big_int(vm, &(&tx_info_ptr + 6))?;
        let nonce = get_big_int(vm, &(&tx_info_ptr + 7))?;

        Ok(TxInfoStruct {
            version,
            account_contract_address,
            max_fee,
            signature_len,
            signature,
            transaction_hash,
            chain_id,
            nonce,
        })
    }
}

/// Represents a contract call, either internal or external.
/// Holds the information needed for the execution of the represented contract call by the OS.
/// No need for validations here, as the fields are taken from validated objects.
#[derive(Debug, PartialEq)]
pub struct CallInfo {
    // static info.
    caller_address: u64, // Should be zero if the call represents an external transaction.
    call_type: Option<CallType>,
    contract_address: u64,
    /// Holds the hash of the executed class; in the case of a library call, it may differ from the
    ///class hash of the called contract state.
    class_hash: Option<Vec<u8>>,
    entry_point_selector: Option<u64>,
    entry_point_type: Option<EntryPointType>,
    calldata: Vec<u64>,
    // Execution info
    retdata: Vec<u64>,
    execution_resources: ExecutionResources,
    // Note that the order starts from a transaction-global offset.
    events: Vec<OrderedEvent>,
    l2_to_l1_messages: Vec<OrderedL2ToL1Message>,
}

impl Default for CallInfo {
    fn default() -> Self {
        let execution_resources = ExecutionResources {
            n_steps: 0,
            n_memory_holes: 0,
            builtin_instance_counter: HashMap::new(),
        };
        Self {
            caller_address: Default::default(),
            call_type: Default::default(),
            contract_address: Default::default(),
            class_hash: Default::default(),
            entry_point_selector: Default::default(),
            entry_point_type: Default::default(),
            calldata: Default::default(),
            retdata: Default::default(),
            execution_resources,
            events: Default::default(),
            l2_to_l1_messages: Default::default(),
        }
    }
}

#[derive(Debug, PartialEq, Default)]
pub enum TransactionType {
    #[default]
    Declare,
    Deploy,
    DeployAccount,
    InitializeBlockInfo,
    InvokeFunction,
    L1Handler,
}

/// Contains the information gathered by the execution of a transaction.
/// Main usages:
/// 1. Supplies hints for the OS run on the corresponding transaction; e.g., internal call results.
/// 2. Stores useful information for users; e.g., L2-to-L1 messages and emitted events.
#[derive(Debug, PartialEq, Default)]
pub struct TransactionExecutionInfo {
    /// Transaction-specific validation call info.
    validate_info: Option<CallInfo>,
    /// Transaction-specific execution call info, None for Declare.
    call_info: Option<CallInfo>,
    /// Fee transfer call info, executed by the BE for account contract transactions
    /// (e.g., declare and invoke).
    fee_transfer_info: Option<CallInfo>,
    /// The actual fee that was charged in Wei.
    actual_fee: Felt,
    /// Actual resources the transaction is charged for, including L1 gas
    /// and OS additional resources estimation.
    actual_resources: HashMap<String, u64>,
    /// Transaction type is used to determine the order of the calls.
    tx_type: Option<TransactionType>,
}

/// Contains the information needed by the OS to guess
/// the response of a contract call.
#[derive(Debug, PartialEq, Default)]
struct ContractCallResponse {
    retdata: Vec<u64>,
}

#[derive(Debug, PartialEq, Default)]
struct StateSelector {
    contract_addresses: HashSet<u64>,
    class_hashes: HashSet<u64>,
}

impl StateSelector {
    pub fn new(contract_addresses: Vec<u64>, class_hashes: Vec<u64>) -> Self {
        StateSelector {
            contract_addresses: HashSet::from_iter(contract_addresses),
            class_hashes: HashSet::from_iter(class_hashes),
        }
    }

    pub fn le(&self, other: &StateSelector) -> bool {
        self.contract_addresses.is_subset(&other.contract_addresses)
            && self.class_hashes.is_subset(&other.class_hashes)
    }
}

impl BitAnd for StateSelector {
    type Output = StateSelector;

    fn bitand(self, rhs: Self) -> Self::Output {
        let class_hashes: HashSet<u64> = self
            .class_hashes
            .intersection(&rhs.class_hashes)
            .cloned()
            .collect();
        let contract_addresses = self
            .contract_addresses
            .intersection(&rhs.contract_addresses)
            .cloned()
            .collect();
        StateSelector {
            contract_addresses,
            class_hashes,
        }
    }
}

impl BitOr for StateSelector {
    type Output = StateSelector;

    fn bitor(self, rhs: Self) -> Self::Output {
        let class_hashes: HashSet<u64> = self
            .class_hashes
            .union(&rhs.class_hashes)
            .cloned()
            .collect();
        let contract_addresses = self
            .contract_addresses
            .union(&rhs.contract_addresses)
            .cloned()
            .collect();
        StateSelector {
            contract_addresses,
            class_hashes,
        }
    }
}

impl Sub for StateSelector {
    type Output = StateSelector;

    fn sub(self, rhs: Self) -> Self::Output {
        let class_hashes: HashSet<u64> = self
            .class_hashes
            .difference(&rhs.class_hashes)
            .cloned()
            .collect();
        let contract_addresses = self
            .contract_addresses
            .difference(&rhs.contract_addresses)
            .cloned()
            .collect();
        StateSelector {
            contract_addresses,
            class_hashes,
        }
    }
}

/// Represents a contract call, either internal or external.
/// Holds the information needed for the execution of the represented contract call by the OS.
/// No need for validations here, as the fields are taken from validated objects.
#[derive(Debug, PartialEq)]
struct ContractCall {
    // static info.
    from_address: u64, // Should be zero if the call represents the parent transaction itself.
    to_address: u64,   // The called contract address.
    // The address that holds the executed code; relevant just for delegate calls, where it may
    // differ from the code of the to_address contract.
    code_address: Option<u64>,
    entry_point_selector: Option<u64>,
    entry_point_type: Option<EntryPointType>,
    calldata: Vec<u64>,
    signature: Vec<u64>,

    // Execution info.
    cairo_usage: ExecutionResources,
    // Note that the order starts from a transaction-global offset.
    events: Vec<OrderedEvent>,
    l2_to_l1_messages: Vec<L2toL1MessageInfo>,
    // Information kept for the StarkNet OS run in the GpsAmbassador.

    // The response of the direct internal calls invoked by this call; kept in the order
    // the OS "guesses" them.
    internal_call_responses: Vec<ContractCallResponse>,
    // A list of values read from storage by this call, **excluding** readings from nested calls.
    storage_read_values: Vec<u64>,
    // A set of storage addresses accessed by this call, **excluding** addresses from nested calls;
    // kept in order to calculate and prepare the commitment tree facts before the StarkNet OS run.
    storage_accessed_addresses: HashSet<u64>,
}

impl Default for ContractCall {
    fn default() -> Self {
        Self {
            from_address: Default::default(),
            to_address: Default::default(),
            code_address: Default::default(),
            entry_point_selector: Default::default(),
            entry_point_type: Default::default(),
            calldata: Default::default(),
            signature: Default::default(),
            cairo_usage: ExecutionResources {
                n_steps: 0,
                n_memory_holes: 0,
                builtin_instance_counter: HashMap::new(),
            },
            events: Default::default(),
            l2_to_l1_messages: Default::default(),
            internal_call_responses: Default::default(),
            storage_read_values: Default::default(),
            storage_accessed_addresses: Default::default(),
        }
    }
}

impl ContractCall {
    pub fn new_with_address(&self, to_address: u64) -> Self {
        ContractCall {
            to_address,
            ..Self::default()
        }
    }

    pub fn state_selector(&self) -> StateSelector {
        let code_address = match self.code_address {
            Some(code_address) => code_address,
            None => self.to_address,
        };
        StateSelector::new(vec![self.to_address, code_address], vec![])
    }
}
