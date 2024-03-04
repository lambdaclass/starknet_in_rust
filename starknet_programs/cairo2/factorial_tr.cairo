#[starknet::interface]
trait IFactorial<TContractState> {
   fn factorial(self: @TContractState, n: felt252) -> felt252;
}

#[starknet::contract]
mod Factorial {
    #[storage]
    struct Storage {
    }

    fn factorial_tr(acc: felt252, n: felt252) -> felt252 {
        if n == 0 || n == 1 {
            acc
        } else {
            factorial_tr(acc*n, n-1)
        }
    }

    #[abi(embed_v0)]
    impl Factorial of super::IFactorial<ContractState> {
        fn factorial(self: @ContractState, n: felt252) -> felt252 {
            factorial_tr(1, n)
        }
    }
}
