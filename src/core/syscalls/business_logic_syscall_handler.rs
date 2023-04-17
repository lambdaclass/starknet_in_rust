#![allow(dead_code)]

use cairo_rs::{types::relocatable::Relocatable, vm::vm_core::VirtualMachine};
use felt::Felt252;

use crate::{
    business_logic::{
        fact_state::state::ExecutionResourcesManager,
        state::{
            contract_storage_state::ContractStorageState,
            state_api::{State, StateReader},
        },
    },
    core::errors::syscall_handler_errors::SyscallHandlerError,
    utils::Address,
};

use super::{
    syscall_handler::SyscallHandler,
    syscall_info::get_syscall_size_from_name,
    syscall_request::{FromPtr, SyscallRequest},
    syscall_response::SyscallResponse,
};

pub struct BusinessLogicSyscallHandler<'a, T: Default + State + StateReader> {
    pub(crate) resources_manager: ExecutionResourcesManager,
    pub(crate) expected_syscall_ptr: Relocatable,
    pub(crate) starknet_storage_state: ContractStorageState<'a, T>,
}

impl<'a, T: Default + State + StateReader> BusinessLogicSyscallHandler<'a, T> {
    fn new(
        state: &'a mut T,
        contract_address: Address,
        resources_manager: ExecutionResourcesManager,
        expected_syscall_ptr: Relocatable,
    ) -> Self {
        let starknet_storage_state = ContractStorageState::new(state, contract_address);
        Self {
            resources_manager,
            expected_syscall_ptr,
            starknet_storage_state,
        }
    }

    fn increment_syscall_count(&mut self, syscall_name: &str) {
        self.resources_manager
            .increment_syscall_counter(syscall_name, 1);
    }

    fn _storage_write(&mut self, key: Felt252, value: Felt252) {
        self.starknet_storage_state.write(&key.to_le_bytes(), value)
    }
}

impl<'a, T: Default + State + StateReader> SyscallHandler for BusinessLogicSyscallHandler<'a, T> {
    #[allow(irrefutable_let_patterns)]
    fn storage_write(
        &mut self,
        vm: &mut VirtualMachine,
        syscall_ptr: Relocatable,
        remaining_gas: u64,
    ) -> Result<SyscallResponse, SyscallHandlerError> {
        let request = if let SyscallRequest::StorageWrite(request) =
            self.read_and_validate_syscall_request("storage_write", vm, syscall_ptr)?
        {
            request
        } else {
            return Err(SyscallHandlerError::ExpectedStorageWriteSyscall);
        };

        if request.reserved != 0.into() {
            return Err(SyscallHandlerError::UnsopportedAddressDomain(
                request.reserved,
            ));
        }

        Ok(SyscallResponse {
            gas: remaining_gas,
            body: None,
        })
    }

    fn read_and_validate_syscall_request(
        &mut self,
        syscall_name: &str,
        vm: &VirtualMachine,
        syscall_ptr: Relocatable,
    ) -> Result<SyscallRequest, SyscallHandlerError> {
        self.increment_syscall_count(syscall_name);
        let syscall_request = self.read_syscall_request(syscall_name, vm, syscall_ptr)?;

        self.expected_syscall_ptr.offset += get_syscall_size_from_name(syscall_name);
        Ok(syscall_request)
    }

    fn read_syscall_request(
        &self,
        syscall_name: &str,
        vm: &VirtualMachine,
        syscall_ptr: Relocatable,
    ) -> Result<SyscallRequest, SyscallHandlerError> {
        match syscall_name {
            "storage_write" => {
                super::syscall_request::StorageWriteRequest::from_ptr(vm, syscall_ptr)
            }
            _ => Err(SyscallHandlerError::UnknownSyscall(
                syscall_name.to_string(),
            )),
        }
    }
}
