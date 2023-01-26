use cairo_rs::{
    hint_processor::hint_processor_definition::HintProcessor,
    types::relocatable::MaybeRelocatable,
    vm::{
        runners::cairo_runner::{CairoArg, CairoRunner, ExecutionResources},
        vm_core::VirtualMachine,
    },
};
use felt::Felt;

use crate::{
    business_logic::fact_state::in_memory_state_reader::InMemoryStateReader,
    core::syscalls::{
        business_logic_syscall_handler::BusinessLogicSyscallHandler,
        syscall_handler::{self, SyscallHandler, SyscallHintProcessor},
    },
};

use super::starknet_runner_error::StarknetRunnerError;
use cairo_rs::types::relocatable::MaybeRelocatable::Int;

pub(crate) struct StarknetRunner {
    pub(crate) cairo_runner: CairoRunner,
    pub(crate) vm: VirtualMachine,
    pub(crate) syscall_handler:
        SyscallHintProcessor<BusinessLogicSyscallHandler<InMemoryStateReader>>,
}

// TODO: implement run_from_entry_pointt (similar to cairo-rs-py and cairo-rs)

impl StarknetRunner {
    pub fn new(
        cairo_runner: CairoRunner,
        vm: VirtualMachine,
        syscall_handler: SyscallHintProcessor<BusinessLogicSyscallHandler<InMemoryStateReader>>,
    ) -> Self {
        StarknetRunner {
            cairo_runner,
            vm,
            syscall_handler,
        }
    }

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

    pub fn get_return_values(&self) -> Result<Vec<Felt>, StarknetRunnerError> {
        self.vm
            .get_return_values(2)
            .map_err(|_| StarknetRunnerError::NumOutOfBounds)?
            .into_iter()
            .map(|val| match val {
                Int(felt) => Ok(felt),
                _ => Err(StarknetRunnerError::NotFeltInReturnValue),
            })
            .collect::<Result<Vec<Felt>, _>>()
    }
}
