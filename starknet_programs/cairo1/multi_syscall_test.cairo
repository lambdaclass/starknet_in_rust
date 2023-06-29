#[contract]
mod multy_syscall {
    use starknet::info::get_caller_address;
    use starknet::info::get_contract_address;
    use starknet::get_execution_info_syscall;
    use starknet::replace_class_syscall;
    use starknet::library_call_syscall;
    use starknet::call_contract_syscall;

    use starknet::storage_access::{StorageAddress, storage_address_try_from_felt252};
    use starknet::ContractAddress;
    use array::{Array, ArrayTrait, Span, SpanTrait};
    use result::ResultTrait;
    use option::OptionTrait;
    use starknet::syscalls::deploy_syscall;
    use starknet::class_hash::ClassHash;

   
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
    fn replace_class_syscall_test(new_class_hash: ClassHash)  {
        replace_class_syscall(new_class_hash);
    }

    #[external]
    fn library_call_syscall_test(class_hash: ClassHash, function_selector: felt252, calldata: Array<felt252>) {
        library_call_syscall(class_hash, function_selector, calldata.span());
    }


    // #[external]
    // fn contract_call_syscall_test(contract_address: ContractAddress, function_selector: felt252, calldata: Array<felt252>) {
    //     call_contract_syscall(class_hash, function_selector, calldata.span());
    // }
} 

