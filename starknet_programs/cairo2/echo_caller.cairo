#[starknet::interface]
trait IContractTrait<TContractState> {
    fn call_echo_contract(
        ref self: TContractState, function_selector: felt252, value: felt252
    ) -> felt252;
}

#[starknet::contract]
mod EchoCaller {
    use starknet::call_contract_syscall;
    use core::array;
    use core::result::ResultTrait;

    #[storage]
    struct Storage {
        balance: felt252,
    }

    #[abi(embed_v0)]
    impl IContractTrait of super::IContractTrait<ContractState> {
        fn call_echo_contract(
            ref self: ContractState, function_selector: felt252, value: felt252
        ) -> felt252 {
            let mut calldata: Array<felt252> = ArrayTrait::new();
            calldata.append(value);
            let callee_addr = starknet::get_contract_address();
            let return_data = call_contract_syscall(callee_addr, function_selector, calldata.span())
                .unwrap();
            *return_data.get(0_usize).unwrap().unbox()
        }
    }
}
