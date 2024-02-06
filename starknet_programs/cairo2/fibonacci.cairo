#[starknet::interface]
trait IFibonacci<TContractState> {
   fn fib(self: @TContractState, a: felt252, b: felt252, n: felt252) -> felt252;
}

#[starknet::contract]
mod Fibonacci {
    #[storage]
    struct Storage {
    }

    #[external(v0)]
    impl Fibonacci of super::IFibonacci<ContractState> {
        fn fib(self: @ContractState, a: felt252, b: felt252, n: felt252) -> felt252 {
            match n {
                0 => a,
                _ => Fibonacci::fib(self, b, a + b, n - 1),
            }
        }
    }
}
