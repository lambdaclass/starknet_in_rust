use starknet::contract_address::ContractAddress;
use starknet::class_hash::ClassHash;
#[starknet::interface]
trait IDeployTest<TContractState> {
    fn deploy_test(self: @TContractState, class_hash: ClassHash, contract_address_salt: felt252, recipient: felt252, name: felt252, decimals: felt252, initial_supply: felt252, symbol: felt252) -> (core::starknet::contract_address::ContractAddress, core::array::Span::<core::felt252>);
}

#[starknet::contract]
mod DeployTest {
    use core::result::ResultTrait;
    use starknet::syscalls::deploy_syscall;
    use starknet::class_hash::ClassHash;
    use starknet::contract_address::ContractAddress;
    use starknet::class_hash::Felt252TryIntoClassHash;
    use option::OptionTrait;
    use traits::TryInto;
    use array::ArrayTrait;

    #[storage]
    struct Storage {
    }

    #[external(v0)]
    impl DeployTest of super::IDeployTest<ContractState> {
        // fn deploy_test(self: @ContractState, class_hash: ClassHash, contract_address_salt: felt252, name_: felt252, symbol_: felt252, decimals: felt252, initial_supply: felt252, recipient: felt252) -> ContractAddress {
        fn deploy_test(self: @ContractState, class_hash: ClassHash, contract_address_salt: felt252, recipient: felt252, name: felt252, decimals: felt252, initial_supply: felt252, symbol: felt252) -> (core::starknet::contract_address::ContractAddress, core::array::Span::<core::felt252>) {
            let mut calldata = ArrayTrait::new();
            calldata.append(recipient);
            calldata.append(name);
            calldata.append(decimals);
            calldata.append(initial_supply);
            calldata.append(symbol);
            // assert(calldata.len() == 5, 'Wrong calldata length');
            deploy_syscall(class_hash, contract_address_salt, calldata.span(), false).unwrap()
        }
    }
}
