use core::starknet::{account::Call, ContractAddress};

#[starknet::interface]
trait IAccount<TContractState> {
    fn __execute__(ref self: TContractState, calls: Array<Call>) -> Span<felt252>;
    fn __validate__(
        self: @TContractState,
        contract_address: ContractAddress,
        entry_point_selector: felt252,
        calldata: Array<felt252>,
    ) -> felt252;
    fn __validate_declare__(self: @TContractState, class_hash: felt252) -> felt252;
    fn __validate_deploy__(
        self: @TContractState,
        class_hash: felt252,
        contract_address_salt: felt252,
        public_key: felt252,
    ) -> felt252;

    fn deploy(
        self: @TContractState,
        class_hash: felt252,
        contract_address_salt: felt252,
        call_data: Array<felt252>,
    ) -> (ContractAddress, Span<felt252>);
}

#[starknet::contract]
mod Account {
    use core::array::ArrayTrait;
    use core::result::ResultTrait;
    use core::option::OptionTrait;
    use core::traits::TryInto;
    use super::{Call, IAccount};
    use core::starknet::{ContractAddress, deploy_syscall};

    #[storage]
    struct Storage {
        public_key: felt252,
    }

    #[constructor]
    fn constructor(ref self: ContractState, public_key: felt252) {
        self.public_key.write(public_key);
    }

    fn validate_transaction(self: @ContractState) -> felt252 {
        core::starknet::VALIDATED
    }

    #[external(v0)]
    impl Account of IAccount<ContractState> {
        fn __execute__(ref self: ContractState, mut calls: Array<Call>) -> Span<felt252> {
            assert(calls.len() == 1_u32, 'MULTI_CALL_NOT_SUPPORTED');

            let Call{to, selector, calldata } = calls.pop_front().expect('YCA: pop_front');
            core::starknet::call_contract_syscall(
                address: to, entry_point_selector: selector, calldata: calldata.span(),
            )
                .expect('YCA: call_contract_syscall')
        }

        fn __validate__(
            self: @ContractState,
            contract_address: ContractAddress,
            entry_point_selector: felt252,
            calldata: Array<felt252>,
        ) -> felt252 {
            validate_transaction(self)
        }

        fn __validate_declare__(self: @ContractState, class_hash: felt252) -> felt252 {
            validate_transaction(self)
        }

        fn __validate_deploy__(
            self: @ContractState,
            class_hash: felt252,
            contract_address_salt: felt252,
            public_key: felt252,
        ) -> felt252 {
            validate_transaction(self)
        }

        fn deploy(
            self: @ContractState,
            class_hash: felt252,
            contract_address_salt: felt252,
            call_data: Array<felt252>,
        ) -> (ContractAddress, Span<felt252>) {
            deploy_syscall(
                class_hash.try_into().unwrap(), contract_address_salt, call_data.span(), false
            )
                .expect('YCA: deploy_syscall')
        }
    }
}
