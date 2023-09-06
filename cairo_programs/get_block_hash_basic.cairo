#[starknet::contract]

mod GetBlockHashBasic {
    use core::debug::PrintTrait;
use core::result::ResultTrait;
use core::starknet::get_block_hash_syscall;
    #[storage]
    struct Storage {
    }

    #[external(v0)]
    fn get_block_hash(self: @ContractState, block_number: u64) -> felt252 {
        //block_number.print();
        get_block_hash_syscall(block_number).unwrap()
    }

}