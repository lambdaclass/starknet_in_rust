#[starknet::interface]
trait IGetBlockHashBasic<TContractState> {
    fn get_block_hash(self: @TContractState, block_number: u64) -> felt252;
}

#[starknet::contract]
mod GetBlockHashBasic {
    use core::{debug::PrintTrait, result::ResultTrait, starknet::get_block_hash_syscall};

    #[storage]
    struct Storage {}

    #[external(v0)]
    impl GetBlockHashBasic of super::IGetBlockHashBasic<ContractState> {
        fn get_block_hash(self: @ContractState, block_number: u64) -> felt252 {
            get_block_hash_syscall(block_number).unwrap()
        }
    }
}