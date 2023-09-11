#![deny(warnings)]

use starknet_in_rust::syscalls::deprecated_business_logic_syscall_handler::DeprecatedBLSyscallHandler;
use cairo_vm::vm;
use cairo_vm::vm::runners::cairo_runner::RunResources;
use std::collections::HashMap;
use criterion::{black_box, criterion_group, criterion_main, Criterion};
use cairo_vm::types::exec_scope::ExecutionScopes;
use std::{any::Any, collections::HashMap};


fn criterion_benchmark(c: &mut Criterion) {
    // Prepare any required setup here. This might include setting up a VirtualMachine, ExecutionScopes, etc.
    let mut vm = vm!();
    let mut exec_scopes = &mut ExecutionScopes::new();
    let hint_data = &any_box!(hint_data);
    let constants = &HashMap::new();

    // Benchmark the execute_hint method
    c.bench_function("execute_hint", |b| b.iter(|| {
        let mut state = CachedState::<InMemoryStateReader>::default();
        let mut syscall_handler = DeprecatedSyscallHintProcessor::new(
            DeprecatedBLSyscallHandler::default_with(&mut state),
            RunResources::default(),
        );
        black_box(
            syscall_handler.execute_hint(&mut vm, &mut exec_scopes, &hint_data, &constants)
        );
    }));
}

criterion_group!(bench, criterion_benchmark);
criterion_main!(bench);
