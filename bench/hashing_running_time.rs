use cairo_vm::hint_processor::hint_processor_definition::HintProcessorLogic;
use cairo_vm::{
    hint_processor::builtin_hint_processor::builtin_hint_processor_definition::HintProcessorData,
    types::exec_scope::ExecutionScopes,
    vm::{runners::cairo_runner::RunResources, vm_core::VirtualMachine},
};
use criterion::{criterion_group, criterion_main, Criterion};
use starknet_in_rust::state::contract_class_cache::NullContractClassCache;
use starknet_in_rust::syscalls::deprecated_syscall_handler::DeprecatedSyscallHintProcessor;
use starknet_in_rust::syscalls::hint_code_map;
use starknet_in_rust::{
    state::{cached_state::CachedState, in_memory_state_reader::InMemoryStateReader},
    syscalls::deprecated_business_logic_syscall_handler::DeprecatedBLSyscallHandler,
};
use std::collections::HashMap;
use std::{any::Any, hint::black_box};

fn criterion_benchmark(c: &mut Criterion) {
    let exec_scopes = &mut ExecutionScopes::new();
    let ids_names = ["syscall_ptr"];
    let references = {
        let mut references = HashMap::<
            usize,
            cairo_vm::hint_processor::hint_processor_definition::HintReference,
        >::new();
        for i in 0..ids_names.len() as i32 {
            references.insert(
                i as usize,
                cairo_vm::hint_processor::hint_processor_definition::HintReference::new_simple(i),
            );
        }
        references
    };

    for (hint_code, hint_name) in &hint_code_map::HINTCODE {
        let mut ids_data = HashMap::<
            String,
            cairo_vm::hint_processor::hint_processor_definition::HintReference,
        >::new();
        for (i, name) in ids_names.iter().enumerate() {
            ids_data.insert(name.to_string(), references.get(&i).unwrap().clone());
        }

        let hint_data: Box<dyn Any> = Box::new(HintProcessorData::new_default(
            hint_code.to_string(),
            ids_data.clone(),
        ));

        // Changed the string passed to bench_function to include the hint_name for unique labeling
        c.bench_function(&format!("execute_hint_{:?}", hint_name), |b| {
            b.iter(|| {
                let mut vm = VirtualMachine::new(false);
                let mut state =
                    CachedState::<InMemoryStateReader, NullContractClassCache>::default();
                let mut syscall_handler = DeprecatedSyscallHintProcessor::new(
                    DeprecatedBLSyscallHandler::default_with(&mut state),
                    RunResources::default(),
                );
                let constants = &HashMap::new();
                let _ = black_box(syscall_handler.execute_hint(
                    &mut vm,
                    exec_scopes,
                    &hint_data,
                    constants,
                ));
            })
        });
    }
}

criterion_group!(bench, criterion_benchmark);
criterion_main!(bench);