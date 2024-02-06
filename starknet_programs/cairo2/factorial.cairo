#[starknet::interface]
trait IFactorial<TContractState> {
   fn factorial(self: @TContractState, n: felt252) -> felt252;
}

#[starknet::contract]
mod Factorial {
    #[storage]
    struct Storage {
    }

    #[external(v0)]
    impl Factorial of super::IFactorial<ContractState> {
        fn factorial(self: @ContractState, n: felt252) -> felt252 {
            match n {
                0 => 1,
                _ => n * Factorial::factorial(self, n-1),
            }
        }
    }
}
