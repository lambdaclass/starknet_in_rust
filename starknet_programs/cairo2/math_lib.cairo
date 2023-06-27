#[starnet::interface]
trait IMath<TContractState> {
    fn square_root(ref self: TContractState, n: felt252) -> felt252;
}


#[starknet::contract]
mod Math {
    use integer::u128_sqrt;
    use core::traits::Into;
    use traits::TryInto;
    use option::OptionTrait;

    #[storage]
    struct Storage{
    }

    #[external(v0)]
    impl Math of super::IMath<ContractState> {
        fn square_root(ref self: ContractState, n: felt252) -> felt252 {
            let n_u128: u128 = n.try_into().unwrap();
            let n_u64: u64 = u128_sqrt(n_u128);
            n_u64.into()
        }
     }
}
