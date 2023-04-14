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
    core::errors::{state_errors::StateError, syscall_handler_errors::SyscallHandlerError},
    utils::Address,
};

use super::{
    syscall_handler::SyscallHandler, syscall_info::get_syscall_size_from_name,
    syscall_request::SyscallRequest,
};

pub struct BusinessLogicSyscallHandler<'a, T: State + StateReader> {
    pub(crate) resources_manager: ExecutionResourcesManager,
    pub(crate) storage: ContractStorageState<'a, T>,
    pub(crate) expected_syscall_ptr: Relocatable,
}

impl<'a, T: Default + State + StateReader> BusinessLogicSyscallHandler<'a, T> {
    pub fn new(
        state: &'a mut T,
        resources_manager: ExecutionResourcesManager,
        expected_syscall_ptr: Relocatable,
        contract_address: Address,
    ) -> Self {
        let storage = ContractStorageState::new(state, contract_address);
        Self {
            storage,
            resources_manager,
            expected_syscall_ptr,
        }
    }
    fn increment_syscall_count(&mut self, syscall_name: &str) {
        self.resources_manager
            .increment_syscall_counter(syscall_name, 1);
    }
}
impl<'a, T> SyscallHandler for BusinessLogicSyscallHandler<'a, T>
where
    T: Default + State + StateReader,
{
    fn _storage_read(&mut self, key: [u8; 32]) -> Result<Felt252, StateError> {
        self.storage.read(&key).cloned()
    }

    fn read_and_validate_syscall_request(
        &mut self,
        syscall_name: &str,
        vm: &VirtualMachine,
        syscall_ptr: Relocatable,
    ) -> Result<SyscallRequest, SyscallHandlerError> {
        self.increment_syscall_count(syscall_name);
        let syscall_request = self.read_syscall_request(syscall_name, vm, syscall_ptr)?;

        self.expected_syscall_ptr.offset += get_syscall_size_from_name(syscall_name); // TODO: THIS LINE USES THE OLD VERSION OF THE SYSCALLS, NEED TO UPDATE IT
        Ok(syscall_request)
    }
}
