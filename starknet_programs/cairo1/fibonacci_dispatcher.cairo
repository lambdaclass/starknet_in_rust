use starknet::ContractAddress;
use array::ArrayTrait;
use array::SpanTrait;
use box::BoxTrait;
use result::ResultTrait;
use option::OptionTrait;


trait FibonacciDispatcherTrait<T> {
    fn fib(self: T, a: felt252, b: felt252, n: felt252) -> felt252;
}

#[derive(Copy, Drop, storage_access::StorageAccess, Serde)]
struct FibonacciLibraryDispatcher {
    class_hash: starknet::ClassHash,
    selector: felt252,
}

impl FibonacciLibraryDispatcherImpl of FibonacciDispatcherTrait<FibonacciLibraryDispatcher> {
    fn fib(
        self: FibonacciLibraryDispatcher, a: felt252, b: felt252, n: felt252
    ) -> felt252 { // starknet::syscalls::library_call_syscall  is called in here

        let mut calldata = ArrayTrait::new();
        calldata.append(a);
        calldata.append(b);
        calldata.append(n);

        let ret = starknet::syscalls::library_call_syscall(self.class_hash, self.selector, calldata.span()).unwrap();
        *ret.get(0_usize).unwrap().unbox()
    }
}

#[contract]
mod Dispatcher {
    use super::FibonacciDispatcherTrait;
    use super::FibonacciLibraryDispatcher;
    use starknet::ContractAddress;

    #[external]
    fn fib(
        class_hash: felt252, selector: felt252, a: felt252, b: felt252, n: felt252
    ) -> felt252 {
        FibonacciLibraryDispatcher {
            class_hash: starknet::class_hash_const::<27727>(),
            selector
        }.fib(a, b, n)
    }
}
