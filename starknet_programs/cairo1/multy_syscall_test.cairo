#[contract]
mod multy_syscall {
    use starknet::info::get_caller_address;
    use starknet::info::get_contract_address;
    use starknet::get_execution_info_syscall;
    use starknet::replace_class_syscall;

    use starknet::storage_access::{StorageAddress, storage_address_try_from_felt252};
    use starknet::contract_address::ContractAddress;
    use array::{Array, ArrayTrait, Span, SpanTrait};
    use result::ResultTrait;
    use option::OptionTrait;
    use starknet::syscalls::deploy_syscall;
    use starknet::class_hash::ClassHash;
    use starknet::class_hash::Felt252TryIntoClassHash;
    use traits::TryInto;
   
    #[external]
    fn caller_address() {
        get_caller_address();
    }

     #[external]
    fn contract_address() {
        get_contract_address();
    }

     #[external]
    fn execution_info_syscall() {
        get_execution_info_syscall();
    }

     #[view]
    fn get_number() -> felt252 {
        25
    }

    #[external]
    fn upgrade(new_class_hash: ClassHash)  {
        replace_class_syscall(new_class_hash);
    }
}