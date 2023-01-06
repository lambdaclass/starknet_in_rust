use cairo_rs::{
    types::relocatable::{MaybeRelocatable, Relocatable},
    vm::vm_core::VirtualMachine,
};
use num_bigint::BigInt;
use num_traits::{ToPrimitive, Zero};

use crate::{
    bigint,
    core::{
        errors::syscall_handler_errors::SyscallHandlerError, syscalls::syscall_request::FromPtr,
    },
    definitions::general_config::StarknetChainId,
    utils::{get_big_int, get_integer, get_relocatable},
};

use super::execution_errors::ExecutionError;

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct OrderedEvent {
    #[allow(unused)] // TODO: remove once used
    order: u64,
    #[allow(unused)] // TODO: remove once used
    keys: Vec<BigInt>,
    #[allow(unused)] // TODO: remove once used
    data: Vec<BigInt>,
}
#[derive(Clone)]
pub(crate) struct TransactionExecutionContext {
    pub(crate) n_emitted_events: u64,
    pub(crate) version: usize,
    pub(crate) account_contract_address: BigInt,
    pub(crate) max_fee: u64,
    pub(crate) transaction_hash: BigInt,
    pub(crate) signature: Vec<BigInt>,
    pub(crate) nonce: BigInt,
    pub(crate) n_sent_messages: usize,
}

impl OrderedEvent {
    pub fn new(order: u64, keys: Vec<BigInt>, data: Vec<BigInt>) -> Self {
        OrderedEvent { order, keys, data }
    }
}

impl TransactionExecutionContext {
    pub fn new() -> Self {
        TransactionExecutionContext {
            n_emitted_events: 0,
            account_contract_address: BigInt::zero(),
            max_fee: 0,
            nonce: BigInt::zero(),
            signature: Vec::new(),
            transaction_hash: BigInt::zero(),
            version: 0,
            n_sent_messages: 0,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct OrderedL2ToL1Message {
    pub(crate) order: usize,
    pub(crate) to_address: usize,
    pub(crate) payload: Vec<BigInt>,
}

impl OrderedL2ToL1Message {
    pub fn new(order: usize, to_address: usize, payload: Vec<BigInt>) -> Self {
        OrderedL2ToL1Message {
            order,
            to_address,
            payload,
        }
    }
}

pub struct L2toL1MessageInfo {
    pub(crate) from_address: usize,
    pub(crate) to_address: usize,
    pub(crate) payload: Vec<BigInt>,
}

impl L2toL1MessageInfo {
    pub(crate) fn new(
        message_content: OrderedL2ToL1Message,
        sending_contract_address: usize,
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
    pub(crate) account_contract_address: BigInt,
    pub(crate) max_fee: u64,
    pub(crate) signature_len: usize,
    pub(crate) signature: Relocatable,
    pub(crate) transaction_hash: BigInt,
    pub(crate) chain_id: BigInt,
    pub(crate) nonce: BigInt,
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
            chain_id: chain_id.to_bigint(),
            nonce: tx.nonce,
        }
    }
    pub(crate) fn to_vec(&self) -> Vec<MaybeRelocatable> {
        vec![
            MaybeRelocatable::from(bigint!(self.version)),
            MaybeRelocatable::from(&self.account_contract_address),
            MaybeRelocatable::from(bigint!(self.max_fee)),
            MaybeRelocatable::from(bigint!(self.signature_len)),
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
            .ok_or(SyscallHandlerError::BigintToU64Fail)?;
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
