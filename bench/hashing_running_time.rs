use std::collections::HashMap;

#[deny(unused_imports)]
use criterion::{criterion_group, criterion_main, Criterion};
use cairo_vm::{vm::{vm_core::VirtualMachine, runners::cairo_runner::RunResources}, types::exec_scope::ExecutionScopes, hint_processor::builtin_hint_processor::builtin_hint_processor_definition::HintProcessorData};
use starknet_in_rust::{state::{cached_state::CachedState, in_memory_state_reader::InMemoryStateReader}, syscalls::deprecated_business_logic_syscall_handler::DeprecatedBLSyscallHandler};
use starknet_in_rust::syscalls::deprecated_syscall_handler::DeprecatedSyscallHintProcessor;
use cairo_vm::hint_processor::hint_processor_definition::HintProcessorLogic;
use std::{hint::black_box, any::Any};

fn criterion_benchmark(c: &mut Criterion) {
    let mut exec_scopes = &mut ExecutionScopes::new();
    let ids_names = vec!["syscall_ptr"];
    let references = {
        let mut references = HashMap::<
            usize,
            cairo_vm::hint_processor::hint_processor_definition::HintReference,
        >::new();
        for i in 0..ids_names.len() as i32 {
            references.insert(
                i as usize,
                cairo_vm::hint_processor::hint_processor_definition::HintReference::new_simple(
                    i as i32,
                ),
            );
        }
        references
    };

    let mut ids_data = HashMap::<String, cairo_vm::hint_processor::hint_processor_definition::HintReference>::new();
    for (i, name) in ids_names.iter().enumerate() {
        ids_data.insert(name.to_string(), references.get(&i).unwrap().clone());
    }


    let hint_data: Box<dyn Any> = Box::new(HintProcessorData::new_default(
        "syscall_handler.get_block_timestamp(segments=segments, syscall_ptr=ids.syscall_ptr)"
            .to_string(),
        ids_data,
    ));


    // Benchmark the execute_hint method
    c.bench_function("execute_hint", |b| b.iter(|| {
        let mut vm = VirtualMachine::new(false);
        let mut state = CachedState::<InMemoryStateReader>::default();
        let mut syscall_handler = DeprecatedSyscallHintProcessor::new(
            DeprecatedBLSyscallHandler::default_with(&mut state),
            RunResources::default(),
        );
        let constants = &HashMap::new();

        let _ = black_box(
            syscall_handler.execute_hint(&mut vm, &mut exec_scopes, &hint_data, &constants)
        );
    }));
}

criterion_group!(bench, criterion_benchmark);
criterion_main!(bench);
