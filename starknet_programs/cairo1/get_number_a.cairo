#[starknet::interface]
trait IGetNumber<TContractState> {
    fn get_number() -> felt252;
    fh upgrade(new_class_hash: ClassHash);
}

#[starknet::contract]
mod GetNumber {
    use core::starknet::class_hash::ClassHash;
    use core::starknet::replace_class_syscall;

    #[external(v0)]
    impl GetNumber of super::IGetNumber<ContractState> { 
        fn upgrade(new_class_hash: ClassHash)  {
            replace_class_syscall(new_class_hash);
        }
    
        fn get_number(self: @ContractState) -> felt252 {
            25
        }
    }
}
