use crate::starknet_runner::runner::StarknetRunner;
use cairo_rs::{types::relocatable::MaybeRelocatable, vm::runners::builtin_runner::BuiltinRunner};
use std::collections::HashMap;

pub fn prepare_os_context(runner: StarknetRunner) -> Vec<MaybeRelocatable> {
    let syscall_segment = runner.vm.add_memory_segment();
    let os_context = [syscall_segment.into()].to_vec();
    let builtin_runners = runner
        .vm
        .get_builtin_runners()
        .to_owned()
        .into_iter()
        .collect::<HashMap<String, BuiltinRunner>>();
    runner
        .cairo_runner
        .get_program_builtins()
        .iter()
        .for_each(|builtin| {
            if builtin_runners.contains_key(builtin) {
                let b_runner = builtin_runners.get(builtin).unwrap();
                let stack = b_runner.initial_stack();
                os_context.extend(stack);
            }
        });
    os_context
}
