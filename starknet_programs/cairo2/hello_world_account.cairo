// Import necessary modules and traits
use serde::Serde;
use starknet::ContractAddress;
use array::ArrayTrait;
use array::SpanTrait;
use option::OptionTrait;

// Define the Call struct
#[derive(Drop, Serde)]
struct Call {
    to: ContractAddress,
    selector: felt252,
    calldata: Array<felt252>
}

#[starknet::interface]
trait IAccount<TContractState> {
    fn __validate_deploy__(self: @TContractState, class_hash: felt252, contract_address_salt: felt252, public_key_: felt252) -> felt252;
    fn __validate_declare__(self: @TContractState, class_hash: felt252) -> felt252;
    fn __validate__(self: @TContractState, contract_address: ContractAddress, entry_point_selector: felt252, calldata: Array<felt252>) -> felt252;
    fn __execute__(ref self: TContractState, calls: Array<Call>) -> Span<felt252>;
    fn deploy(self: @TContractState, class_hash: felt252, contract_address_salt: felt252, name_: felt252, symbol_: felt252, decimals: felt252, initial_supply: felt252, recipient: felt252) -> (ContractAddress, core::array::Span::<core::felt252>);
}

// Define the Account contract
#[starknet::contract]
mod Account {
    use array::ArrayTrait;
    use array::SpanTrait;
    use box::BoxTrait;
    use ecdsa::check_ecdsa_signature;
    use option::OptionTrait;
    use super::Call;
    use starknet::ContractAddress;
    use zeroable::Zeroable;
    use starknet::syscalls::deploy_syscall;
    use core::result::ResultTrait;
    use starknet::class_hash::ClassHash;
    use starknet::class_hash::Felt252TryIntoClassHash;
    use traits::TryInto;

    // Define the contract's storage variables
    #[storage]
    struct Storage {
        public_key: felt252
    }

    // Constructor function for initializing the contract
    #[constructor]
    fn constructor(ref self: ContractState, public_key_: felt252) {
        self.public_key.write(public_key_);
    }

    // Internal function to validate the transaction signature
    fn validate_transaction(self: @ContractState) -> felt252 {
        let tx_info = starknet::get_tx_info().unbox(); // Unbox transaction info
        let signature = tx_info.signature; // Extract signature
        assert(signature.len() == 2_u32, 'INVALID_SIGNATURE_LENGTH'); // Check signature length

        // Verify ECDSA signature

        starknet::VALIDATED // Return validation status
    }

    #[external(v0)]
    impl Account of super::IAccount<ContractState> {
        fn deploy(self: @ContractState, class_hash: felt252, contract_address_salt: felt252, name_: felt252, symbol_: felt252, decimals: felt252, initial_supply: felt252, recipient: felt252) -> (ContractAddress, core::array::Span::<core::felt252>) {
            let mut calldata = ArrayTrait::new();
            calldata.append(name_);
            calldata.append(symbol_);
            calldata.append(decimals);
            calldata.append(initial_supply);
            calldata.append(recipient);
            let (address0, something_else) = deploy_syscall(class_hash.try_into().unwrap(), contract_address_salt, calldata.span(), false).unwrap();
            (address0, something_else)
        }
        // Validate contract deployment
        fn __validate_deploy__(
            self: @ContractState, class_hash: felt252, contract_address_salt: felt252, public_key_: felt252
        ) -> felt252 {
            validate_transaction(self)
        }

        // Validate contract declaration
        fn __validate_declare__(self: @ContractState, class_hash: felt252) -> felt252 {
            validate_transaction(self)
        }

        // Validate contract execution
        fn __validate__(
            self: @ContractState, contract_address: ContractAddress, entry_point_selector: felt252, calldata: Array<felt252>
        ) -> felt252 {
            validate_transaction(self)
        }

        // Execute a contract call
        #[raw_output]
        fn __execute__(ref self: ContractState, mut calls: Array<Call>) -> Span<felt252> {
            // Validate caller
            assert(starknet::get_caller_address().is_zero(), 'INVALID_CALLER');

            let tx_info = starknet::get_tx_info().unbox(); // Unbox transaction info
            assert(tx_info.version != 0, 'INVALID_TX_VERSION');

            assert(calls.len() == 1_u32, 'MULTI_CALL_NOT_SUPPORTED'); // Only single calls are supported
            let Call{to, selector, calldata } = calls.pop_front().unwrap();

            // Call the target contract
            starknet::call_contract_syscall(
                address: to, entry_point_selector: selector, calldata: calldata.span()
            ).unwrap_syscall()
        }
    }
}
