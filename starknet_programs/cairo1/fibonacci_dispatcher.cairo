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
            // THIS VALUE IS THE HASH OF THE FIBONACCI CASM CLASS HASH. THE SAME AS THE CONSTANT: TEST_FIB_COMPILED_CONTRACT_CLASS_HASH
            class_hash: starknet::class_hash_const::<1948962768849191111780391610229754715773924969841143100991524171924131413970>(),
            selector
        }.fib(a, b, n)
    }
}
