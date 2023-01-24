use cairo_rs::{
    hint_processor::hint_processor_definition::HintProcessor,
    types::relocatable::MaybeRelocatable,
    vm::{
        runners::cairo_runner::{CairoArg, CairoRunner, ExecutionResources},
        vm_core::VirtualMachine,
    },
};

use crate::core::syscalls::{
    business_logic_syscall_handler::BusinessLogicSyscallHandler,
    syscall_handler::{self, SyscallHandler, SyscallHintProcessor},
};

pub(crate) struct StarknetRunner {
    cairo_runner: CairoRunner,
    vm: VirtualMachine,
    syscall_handler: SyscallHintProcessor<BusinessLogicSyscallHandler>,
}

// TODO: implement run_from_entry_pointt (similar to cairo-rs-py and cairo-rs)

impl StarknetRunner {
    pub fn run_from_entrypoint(&mut self, entrypoint: usize, args: &[&CairoArg]) {
        let verify_secure = true;
        let args: Vec<&CairoArg> = args.iter().map(ToOwned::to_owned).collect();

        self.cairo_runner.run_from_entrypoint(
            entrypoint,
            &args,
            verify_secure,
            &mut self.vm,
            &mut self.syscall_handler,
        );
    }

    pub fn get_execution_resources(&self) -> ExecutionResources {
        self.cairo_runner.get_execution_resources(&self.vm).unwrap()
    }

    pub fn get_return_values(&self) -> Vec<MaybeRelocatable> {
        self.vm.get_return_values(2).unwrap()
    }
}
