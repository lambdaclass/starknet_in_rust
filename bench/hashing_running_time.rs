#[deny(unused_imports)]
use criterion::{criterion_group, criterion_main, Criterion};
use cairo_vm::vm::vm_core::VirtualMachine;


fn criterion_benchmark(c: &mut Criterion) {
    let mut vm = VirtualMachine::new(false);
    // let mut exec_scopes = &mut ExecutionScopes::new();
    // let hint_data = &any_box!(hint_data);
    // let constants = &HashMap::new();

    // Benchmark the execute_hint method
    c.bench_function("execute_hint", |b| b.iter(|| {
        // let mut state = CachedState::<InMemoryStateReader>::default();
        // let mut syscall_handler = DeprecatedSyscallHintProcessor::new(
        //     DeprecatedBLSyscallHandler::default_with(&mut state),
        //     RunResources::default(),
        // );
        // black_box(
        //     syscall_handler.execute_hint(&mut vm, &mut exec_scopes, &hint_data, &constants)
        // );
    }));
}

criterion_group!(bench, criterion_benchmark);
criterion_main!(bench);
