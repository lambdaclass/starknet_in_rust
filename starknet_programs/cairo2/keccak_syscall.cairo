#[starknet::interface]
trait IKeccak<TContractState> {
   fn keccak(self: @TContractState) -> felt252;
}

#[starknet::contract]
mod Keccak {
    use array::{Array, ArrayTrait};
    use core::traits::Into;

    #[storage]
    struct Storage {
    }

    #[external(v0)]
    impl Keccak of super::IKeccak<ContractState> {
        fn keccak(self: @ContractState) -> felt252 {
            let n: u64 = 124152;
            let mut arr = ArrayTrait::new();
            arr.append(n);
            let res: u256 = keccak::cairo_keccak(ref arr, 0, 0);
            res.low.into()
        }
    }
}
