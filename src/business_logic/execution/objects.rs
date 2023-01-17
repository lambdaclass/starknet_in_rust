use std::collections::{HashMap, HashSet, VecDeque};

use cairo_rs::{
    types::relocatable::{MaybeRelocatable, Relocatable},
    vm::{runners::cairo_runner::ExecutionResources, vm_core::VirtualMachine},
};
use felt::{Felt, NewFelt};
use num_traits::{ToPrimitive, Zero};

use super::execution_errors::ExecutionError;
use crate::{
    business_logic::state::state_cache::StorageEntry,
    core::{
        errors::syscall_handler_errors::SyscallHandlerError, syscalls::syscall_request::FromPtr,
    },
    definitions::{general_config::StarknetChainId, transaction_type::TransactionType},
    utils::{get_big_int, get_integer, get_relocatable, Address},
};
use crate::{services::api::contract_class::EntryPointType, starknet_storage::storage::Storage};

type ResourcesMapping = HashMap<String, Felt>;

#[derive(Debug, Clone, PartialEq)]
pub(crate) enum CallType {
    Call,
    Delegate,
}

// --------------------
// CallInfo structure
// --------------------

#[derive(Debug, Clone, PartialEq)]
pub struct CallInfo {
    pub(crate) caller_address: Address,
    pub(crate) call_type: Option<CallType>,
    pub(crate) contract_address: Address,
    pub(crate) class_hash: Option<Felt>,
    pub(crate) entry_point_selector: Option<usize>,
    pub(crate) entry_point_type: Option<EntryPointType>,
    pub(crate) calldata: VecDeque<Felt>,
    pub(crate) retdata: VecDeque<u64>,
    pub(crate) execution_resources: ExecutionResources,
    pub(crate) events: VecDeque<OrderedEvent>,
    pub(crate) l2_to_l1_messages: VecDeque<OrderedL2ToL1Message>,
    pub(crate) storage_read_values: VecDeque<u64>,
    pub(crate) accesed_storage_keys: VecDeque<[u8; 32]>,
    pub(crate) internal_calls: Vec<CallInfo>,
}

impl CallInfo {
    pub fn get_visited_storage_entries(self) -> HashSet<StorageEntry> {
        let mut storage_entries = self
            .accesed_storage_keys
            .into_iter()
            .map(|key| (self.contract_address.clone(), key))
            .collect::<HashSet<(Address, [u8; 32])>>();

        let internal_visited_storage_entries =
            CallInfo::get_visited_storage_entries_of_many(self.internal_calls);

        storage_entries.extend(internal_visited_storage_entries);
        storage_entries
    }

    pub fn get_visited_storage_entries_of_many(calls_info: Vec<CallInfo>) -> HashSet<StorageEntry> {
        calls_info.into_iter().fold(HashSet::new(), |mut acc, c| {
            acc.extend(c.get_visited_storage_entries());
            acc
        })
    }
}

impl Default for CallInfo {
    fn default() -> Self {
        Self {
            caller_address: Address(0.into()),
            call_type: None,
            contract_address: Address(0.into()),
            class_hash: None,
            internal_calls: Vec::new(),
            entry_point_type: Some(EntryPointType::Constructor),
            storage_read_values: VecDeque::new(),
            retdata: VecDeque::new(),
            entry_point_selector: None,
            l2_to_l1_messages: VecDeque::new(),
            accesed_storage_keys: VecDeque::new(),
            calldata: VecDeque::new(),
            execution_resources: ExecutionResources {
                n_steps: 0,
                n_memory_holes: 0,
                builtin_instance_counter: HashMap::new(),
            },
            events: VecDeque::new(),
        }
    }
}

// -------------------------
//  Events Structures
// -------------------------

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct OrderedEvent {
    order: u64,
    keys: Vec<Felt>,
    data: Vec<Felt>,
}

impl OrderedEvent {
    pub fn new(order: u64, keys: Vec<Felt>, data: Vec<Felt>) -> Self {
        OrderedEvent { order, keys, data }
    }
}

// -------------------------
//  Transaction Structures
// -------------------------

#[derive(Clone)]
pub(crate) struct TransactionExecutionContext {
    pub(crate) n_emitted_events: u64,
    pub(crate) version: usize,
    pub(crate) account_contract_address: Address,
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
            account_contract_address: Address(Felt::zero()),
            max_fee: 0,
            nonce: Felt::zero(),
            signature: Vec::new(),
            transaction_hash: Felt::zero(),
            version: 0,
            n_sent_messages: 0,
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub(crate) struct TxInfoStruct {
    pub(crate) version: usize,
    pub(crate) account_contract_address: Address,
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
            MaybeRelocatable::from(&self.account_contract_address.0),
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

        let account_contract_address = Address(get_big_int(vm, &(&tx_info_ptr + 1))?);
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

#[derive(Debug, PartialEq, Default)]
pub struct TransactionExecutionInfo {
    pub(crate) validate_info: Option<CallInfo>,
    pub(crate) call_info: Option<CallInfo>,
    pub(crate) fee_transfer_info: Option<CallInfo>,
    pub(crate) actual_fee: u64,
    pub(crate) actual_resources: ResourcesMapping,
    pub(crate) tx_type: Option<TransactionType>,
}

impl TransactionExecutionInfo {
    pub fn new(
        validate_info: Option<CallInfo>,
        call_info: Option<CallInfo>,
        fee_transfer_info: Option<CallInfo>,
        actual_fee: u64,
        actual_resources: ResourcesMapping,
        tx_type: Option<TransactionType>,
    ) -> Self {
        TransactionExecutionInfo {
            validate_info,
            call_info,
            fee_transfer_info,
            actual_fee,
            actual_resources,
            tx_type,
        }
    }

    pub fn from_concurrent_state_execution_info(
        concurrent_execution_info: TransactionExecutionInfo,
        actual_fee: u64,
        fee_transfer_info: Option<CallInfo>,
    ) -> Self {
        TransactionExecutionInfo {
            actual_fee,
            fee_transfer_info,
            ..concurrent_execution_info
        }
    }

    // In deploy account tx, validation will take place after execution of the constructor.
    pub fn non_optional_calls(&self) -> Vec<CallInfo> {
        let calls = match self.tx_type {
            Some(TransactionType::Deploy) => [
                self.call_info.clone(),
                self.validate_info.clone(),
                self.fee_transfer_info.clone(),
            ],
            _ => [
                self.validate_info.clone(),
                self.call_info.clone(),
                self.fee_transfer_info.clone(),
            ],
        };

        calls.into_iter().flatten().collect()
    }

    pub fn get_visited_storage_entries_of_many(&self) -> Vec<StorageEntry> {
        CallInfo::get_visited_storage_entries_of_many(self.non_optional_calls());
        todo!()
    }
}

// --------------------
// Messages Structures
// --------------------

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct OrderedL2ToL1Message {
    pub(crate) order: usize,
    pub(crate) to_address: Address,
    pub(crate) payload: Vec<Felt>,
}

impl OrderedL2ToL1Message {
    pub fn new(order: usize, to_address: Address, payload: Vec<Felt>) -> Self {
        OrderedL2ToL1Message {
            order,
            to_address,
            payload,
        }
    }
}

pub struct L2toL1MessageInfo {
    pub(crate) from_address: Address,
    pub(crate) to_address: Address,
    pub(crate) payload: Vec<Felt>,
}

impl L2toL1MessageInfo {
    pub(crate) fn new(
        message_content: OrderedL2ToL1Message,
        sending_contract_address: Address,
    ) -> Self {
        L2toL1MessageInfo {
            from_address: sending_contract_address,
            to_address: message_content.to_address,
            payload: message_content.payload,
        }
    }
}

#[cfg(test)]
mod tests {

    use crate::business_logic::execution::objects::CallInfo;

    use super::TransactionExecutionInfo;

    #[test]
    fn non_optional_calls_test() {
        let mut tx_info = TransactionExecutionInfo {
            ..Default::default()
        };
        tx_info.call_info = Some(CallInfo {
            ..Default::default()
        });
        tx_info.validate_info = Some(CallInfo {
            ..Default::default()
        });
        tx_info.fee_transfer_info = None;

        let res = tx_info.non_optional_calls();
        assert_eq!(
            res,
            [
                CallInfo {
                    ..Default::default()
                },
                CallInfo {
                    ..Default::default()
                }
            ]
        );

        tx_info.call_info = None;
        tx_info.validate_info = None;
        tx_info.fee_transfer_info = None;

        let res = tx_info.non_optional_calls();
        assert_eq!(res, [])
    }
}
