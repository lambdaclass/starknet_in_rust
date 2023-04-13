use cairo_rs::types::relocatable::Relocatable;

use crate::{
    business_logic::{
        execution::objects::{OrderedEvent, TransactionExecutionContext},
        fact_state::state::ExecutionResourcesManager,
    },
    core::errors::syscall_handler_errors::SyscallHandlerError,
    utils::{get_integer_range, Address},
};

use super::syscall_request::SyscallRequest;

#[allow(unused)]
pub struct BusinessLogicSyscallHandler {
    pub(crate) events: Vec<OrderedEvent>,
    pub(crate) expected_syscall_ptr: Relocatable,
    pub(crate) resources_manager: ExecutionResourcesManager,
    pub(crate) tx_execution_context: TransactionExecutionContext,
}

impl BusinessLogicSyscallHandler {
    #[allow(unused)]
    /// Increments the syscall count for a given `syscall_name` by 1.
    fn increment_syscall_count(&mut self, syscall_name: &str) {
        self.resources_manager
            .increment_syscall_counter(syscall_name, 1);
    }
}

impl SyscallHandler for BusinessLogicSyscallHandler {
    //     fn read_and_validate_syscall_request(
    //         &mut self,
    //         syscall_name: &str,
    //         vm: &VirtualMachine,
    //         syscall_ptr: Relocatable,
    //     ) -> Result<SyscallRequest, SyscallHandlerError> {
    //         self.increment_syscall_count(syscall_name);

    //         let syscall_request = self.read_syscall_request(syscall_name, vm, syscall_ptr)?;

    //         self.expected_syscall_ptr.offset += get_syscall_size_from_name(syscall_name);
    //         Ok(syscall_request)
    //     }

    fn syscall_deploy(
        &mut self,
        vm: &VirtualMachine,
        syscall_ptr: Relocatable,
    ) -> Result<Address, SyscallHandlerError> {
        let request = if let SyscallRequest::Deploy(request) =
            self.read_and_validate_syscall_request("deploy", vm, syscall_ptr)?
        {
            request
        } else {
            return Err(SyscallHandlerError::ExpectedDeployRequestStruct);
        };

        if !(request.deploy_from_zero.is_zero() || request.deploy_from_zero.is_one()) {
            return Err(SyscallHandlerError::DeployFromZero(
                request.deploy_from_zero,
            ));
        };

        let constructor_calldata = get_integer_range(
            vm,
            request.constructor_calldata,
            request
                .constructor_calldata_size
                .to_usize()
                .ok_or(SyscallHandlerError::FeltToUsizeFail)?,
        )?;

        let class_hash = &request.class_hash;

        let deployer_address = if request.deploy_from_zero.is_zero() {
            self.contract_address.clone()
        } else {
            Address(0.into())
        };

        let deploy_contract_address = Address(calculate_contract_address(
            &Address(request.contract_address_salt),
            class_hash,
            &constructor_calldata,
            deployer_address,
        )?);

        // Initialize the contract.
        let class_hash_bytes: ClassHash = felt_to_hash(&request.class_hash);

        self.starknet_storage_state
            .state
            .deploy_contract(deploy_contract_address.clone(), class_hash_bytes)?;
        self.execute_constructor_entry_point(
            &deploy_contract_address,
            class_hash_bytes,
            constructor_calldata,
        )?;
        Ok(deploy_contract_address)
    }

    //     fn allocate_segment(
    //         &mut self,
    //         vm: &mut VirtualMachine,
    //         data: Vec<MaybeRelocatable>,
    //     ) -> Result<Relocatable, SyscallHandlerError> {
    //         todo!()
    //     }
}
