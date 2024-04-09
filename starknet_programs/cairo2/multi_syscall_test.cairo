use starknet::contract_address::ContractAddress;
use starknet::class_hash::ClassHash;

#[starknet::interface]
trait IMultiSyscall<TContractState> {
        fn caller_address(self: @TContractState) -> ContractAddress;
        fn contract_address(self: @TContractState) -> ContractAddress;
        fn execution_info_syscall(self: @TContractState) -> (ContractAddress, ContractAddress);
        fn test_library_call_syscall(self: @TContractState, class_hash: ClassHash, function_selector: felt252, number: felt252) -> felt252;
        fn test_call_contract_syscall(self: @TContractState, function_selector: felt252, number: felt252) -> felt252;
        fn test_send_message_to_l1(self: @TContractState, to_address: felt252, payload_0: felt252, payload_1: felt252);
        fn read(self: @TContractState)-> felt252;
        fn trigger_events(ref self: TContractState);
        fn get_number(self: @TContractState, number: felt252) -> felt252;
}

#[starknet::contract]
mod MultiSyscall {
    use core::starknet::{get_caller_address, get_contract_address, get_execution_info_syscall, replace_class_syscall,library_call_syscall, call_contract_syscall, send_message_to_l1_syscall, storage_read_syscall, storage_write_syscall, deploy_syscall};
    use starknet::storage_access::{StorageAddress, storage_address_try_from_felt252};
    use starknet::contract_address::ContractAddress;
    use array::{Array, ArrayTrait, Span, SpanTrait};
    use result::ResultTrait;
    use starknet::info::ExecutionInfo;
    use option::OptionTrait;
    use starknet::class_hash::{ClassHash, Felt252TryIntoClassHash};
    use box::{Box, BoxTrait};
    use traits::{Into, TryInto};

    #[storage]
    struct Storage {
        value: u128,
    }

    #[derive(Copy, Drop, PartialEq, starknet::Event)]
    struct StaticEvent {
        n: felt252,
    }

    #[event]
    #[derive(Copy, Drop, PartialEq, starknet::Event)]
    enum Event {
        StaticEvent: StaticEvent,
    }


    #[abi(embed_v0)]
    impl MultiSyscall of super::IMultiSyscall<ContractState> {
        fn caller_address(self: @ContractState) -> ContractAddress {
            get_caller_address()
        }
        fn contract_address(self: @ContractState) ->  ContractAddress {
            get_contract_address()
        }
        fn execution_info_syscall(self: @ContractState) -> (ContractAddress, ContractAddress) {
            let return_data = get_execution_info_syscall().unwrap().unbox();
            (return_data.caller_address, return_data.contract_address)
        }
        fn test_library_call_syscall(self: @ContractState, class_hash: ClassHash, function_selector: felt252, number: felt252) -> felt252 {
            let mut calldata = ArrayTrait::<felt252>::new();
            calldata.append(number);
            let return_data = library_call_syscall(class_hash, function_selector, calldata.span()).unwrap();
            *return_data.get(0_usize).unwrap().unbox()
        }
        fn test_call_contract_syscall(self: @ContractState, function_selector: felt252, number: felt252) -> felt252 {
            let mut calldata = ArrayTrait::<felt252>::new();
            calldata.append(number);
            let return_data =  call_contract_syscall(get_contract_address(), function_selector, calldata.span()).unwrap();
            *return_data.get(0_usize).unwrap().unbox()
        }

        fn test_send_message_to_l1(self: @ContractState, to_address: felt252, payload_0: felt252, payload_1: felt252) {
            let mut calldata = ArrayTrait::<felt252>::new();
            calldata.append(payload_0);
            calldata.append(payload_1);
            let return_data = send_message_to_l1_syscall(to_address,  calldata.span()).unwrap();
            return_data
        }
        fn read(self: @ContractState)-> felt252{
            //write to storage
            let address = storage_address_try_from_felt252(3534535754756246375475423547453).unwrap();
            storage_write_syscall(0, address, 'Hello').unwrap();

            //read from storage
            match storage_read_syscall(0, address) {
                Result::Ok(value) => value,
                Result::Err(revert_reason) => *revert_reason.span().at(0),
            }
        }
        fn trigger_events(ref self: ContractState) {
            self.emit(Event::StaticEvent(StaticEvent {n: 1}));
            self.emit(Event::StaticEvent(StaticEvent {n: 2}));
            self.emit(Event::StaticEvent(StaticEvent {n: 3}));
        }
        fn get_number(self: @ContractState, number: felt252) -> felt252 {
            number
        }
    }
}
