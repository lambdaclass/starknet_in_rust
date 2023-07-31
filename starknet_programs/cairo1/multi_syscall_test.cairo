#[contract]
mod multy_syscall {
    use starknet::get_caller_address;
    use starknet::get_contract_address;
    use starknet::get_execution_info_syscall;
    use starknet::replace_class_syscall;
    use starknet::library_call_syscall;
    use starknet::call_contract_syscall;
    use starknet::send_message_to_l1_syscall;
    use starknet::storage_read_syscall;
    use starknet::storage_write_syscall;
    use starknet::deploy_syscall;

    use starknet::storage_access::{StorageAddress, storage_address_try_from_felt252};
    use starknet::contract_address::ContractAddress;
    use array::{Array, ArrayTrait, Span, SpanTrait};
    use result::ResultTrait;
    use option::OptionTrait;
    use starknet::class_hash::ClassHash;
    use traits::TryInto;
    use starknet::class_hash::Felt252TryIntoClassHash;
    use box::Box;
    use traits::Into;
    use box::BoxTrait;
    use zeroable::Zeroable;
   
    #[external]
    fn caller_address() -> ContractAddress {
        get_caller_address()
    }

     #[external]
    fn contract_address() ->  ContractAddress {
        get_contract_address()
    }

     #[external]
    fn execution_info_syscall() {
        get_execution_info_syscall();
    } 

    #[external]
    fn replace_class_syscall_test(new_class_hash: ClassHash)  {
        replace_class_syscall(new_class_hash);
    }

    #[external]
    fn test_library_call_syscall(class_hash: ClassHash, function_selector: felt252, number: felt252) ->  felt252 {
        let mut calldata = ArrayTrait::new();
        calldata.append(number);
        let return_data = library_call_syscall(class_hash, function_selector, calldata.span()).unwrap();
        *return_data.get(0_usize).unwrap().unbox()
    }

     #[external]
    fn test_call_contract_syscall(function_selector: felt252, number: felt252) ->  felt252 {
        let mut calldata = ArrayTrait::new();
        calldata.append(number);
        let return_data =  call_contract_syscall(get_contract_address(), function_selector, calldata.span()).unwrap();
        *return_data.get(0_usize).unwrap().unbox()
       
    }   
    
    #[external]
    fn test_send_message_to_l1(to_address: felt252, payload_0: felt252, payload_1: felt252) ->  () {
        let mut calldata = ArrayTrait::new();
        calldata.append(payload_0);
        calldata.append(payload_1);
        let return_data = send_message_to_l1_syscall(to_address,  calldata.span()).unwrap();
        return_data
    }

     #[external]
    fn read()-> felt252{
        //write to storage
       let address = storage_address_try_from_felt252(3534535754756246375475423547453).unwrap();
        storage_write_syscall(0, address, 'Hello');

       //read from storage
        match storage_read_syscall(0, address) {
            Result::Ok(value) => value,
            Result::Err(revert_reason) => *revert_reason.span().at(0),
        }
    }

    #[event]
    fn EmitEvent(n: felt252){}

    #[external]
    fn trigger_events() {
        EmitEvent(1);
        EmitEvent(2);
        EmitEvent(3);
    }

    #[external]
    fn deploy_test(class_hash: felt252, contract_address_salt: felt252,) -> ContractAddress {
        let mut calldata = ArrayTrait::new();
        calldata.append(100);
        let (address0, _) = deploy_syscall(class_hash.try_into().unwrap(), contract_address_salt, calldata.span(), false).unwrap();
        address0
    }

    #[external]
    fn get_number(number: felt252) -> felt252 {
        number
    }
}
