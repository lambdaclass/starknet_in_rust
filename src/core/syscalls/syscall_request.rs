use crate::core::errors::syscall_handler_errors::SyscallHandlerError;
use crate::utils::{get_big_int, get_integer, get_relocatable};
use cairo_rs::types::relocatable::Relocatable;
use cairo_rs::vm::vm_core::VirtualMachine;
use num_bigint::BigInt;

pub(crate) enum SyscallRequest {
    EmitEvent(EmitEventStruct),
    GetTxInfo(GetTxInfoStruct),
}

#[derive(Clone, Debug)]
pub(crate) struct EmitEventStruct {
    #[allow(unused)] // TODO: Remove once used.
    pub(crate) selector: BigInt,
    pub(crate) keys_len: usize,
    pub(crate) keys: Relocatable,
    pub(crate) data_len: usize,
    pub(crate) data: Relocatable,
}

pub(crate) trait FromPtr {
    fn from_ptr(
        vm: &VirtualMachine,
        syscall_ptr: Relocatable,
    ) -> Result<SyscallRequest, SyscallHandlerError>;
}

impl From<EmitEventStruct> for SyscallRequest {
    fn from(emit_event_struct: EmitEventStruct) -> SyscallRequest {
        SyscallRequest::EmitEvent(emit_event_struct)
    }
}

impl FromPtr for EmitEventStruct {
    fn from_ptr(
        vm: &VirtualMachine,
        syscall_ptr: Relocatable,
    ) -> Result<SyscallRequest, SyscallHandlerError> {
        let selector = get_big_int(vm, &(syscall_ptr))?;
        let keys_len = get_integer(vm, &(&syscall_ptr + 1))?;
        let keys = get_relocatable(vm, &(&syscall_ptr + 2))?;
        let data_len = get_integer(vm, &(&syscall_ptr + 3))?;
        let data = get_relocatable(vm, &(&syscall_ptr + 4))?;

        Ok(EmitEventStruct {
            selector,
            keys_len,
            keys,
            data_len,
            data,
        }
        .into())
    }
}

#[allow(unused)] // TODO: Remove once used.
#[derive(Debug, Clone)]
pub(crate) struct GetTxInfoStruct {
    pub(crate) version: BigInt,
    pub(crate) account_contract_address: BigInt,
    pub(crate) max_fee: BigInt,
    pub(crate) signature_len: usize,
    pub(crate) signature: Relocatable,
    pub(crate) transaction_hash: BigInt,
    pub(crate) chain_id: BigInt,
    pub(crate) nonce: BigInt,
}

impl From<GetTxInfoStruct> for SyscallRequest {
    fn from(get_tx_info_struct: GetTxInfoStruct) -> SyscallRequest {
        SyscallRequest::GetTxInfo(get_tx_info_struct)
    }
}

impl FromPtr for GetTxInfoStruct {
    fn from_ptr(
        vm: &VirtualMachine,
        syscall_ptr: Relocatable,
    ) -> Result<SyscallRequest, SyscallHandlerError> {
        let version = get_big_int(vm, &(syscall_ptr))?;
        let account_contract_address = get_big_int(vm, &(&syscall_ptr + 1))?;
        let max_fee = get_big_int(vm, &(&syscall_ptr + 2))?;
        let signature_len = get_integer(vm, &(&syscall_ptr + 3))?;
        let signature = get_relocatable(vm, &(&syscall_ptr + 4))?;
        let transaction_hash = get_big_int(vm, &(&syscall_ptr + 5))?;
        let chain_id = get_big_int(vm, &(&syscall_ptr + 6))?;
        let nonce = get_big_int(vm, &(&syscall_ptr + 7))?;
        
        Ok(GetTxInfoStruct {
            version,
            account_contract_address,
            max_fee,
            signature_len,
            signature,
            transaction_hash,
            chain_id,
            nonce,
        }
        .into())
    }
}
