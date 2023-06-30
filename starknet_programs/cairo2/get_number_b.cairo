use core::starknet::class_hash::ClassHash;

#[starknet::interface]
trait IGetNumber<TContractState> {
    fn get_number(self: @TContractState) -> felt252;
    fn upgrade(self: @TContractState, new_class_hash: ClassHash);
}

#[starknet::contract]
mod GetNumber {
    use core::starknet::class_hash::ClassHash;
    use core::starknet::replace_class_syscall;

    #[storage]
    struct Storage {
    }

    #[external(v0)]
    impl GetNumber of super::IGetNumber<ContractState> {
        fn get_number(self: @ContractState) -> felt252 {
            17
        }

        fn upgrade(self: @ContractState, new_class_hash: ClassHash)  {
            replace_class_syscall(new_class_hash);
        }
    }
}
