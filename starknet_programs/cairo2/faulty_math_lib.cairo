#[starknet::interface]
trait IMath<TContractState> {
    fn square_root(self: @TContractState, n: felt252) -> felt252;
}

#[starknet::contract]
mod Math {
    use integer::u128_sqrt;
    use core::traits::Into;
    use traits::TryInto;
    use option::OptionTrait;

    #[storage]
    struct Storage {
    }

    #[external(v0)]
    impl Math of super::IMath<ContractState> {
        fn square_root(self: @ContractState, n: felt252) -> felt252 {
            assert( 0 == 1 , 'Unimplemented');
            0
        }
    }
}
