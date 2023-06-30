use starknet::ClassHash;

#[starknet::interface]
trait GetNumber<TContractState> {
    fn get_number(self: @TContractState) -> felt252;
    fn upgrade(self: @TContractState, new_class_hash: ClassHash);
}

#[starknet::interface]
trait IGetNumber<TContractState> {
    fn get_number(self: @TContractState) -> felt252;
    fn upgrade(self: @TContractState, new_class_hash: ClassHash);
    fn get_numbers_old_new(self: @TContractState, new_class_hash: ClassHash) -> (felt252, felt252);
}

#[starknet::contract]
mod GetNumberWrapper {
    use super::GetNumberDispatcherTrait; 
    use super::GetNumberDispatcher;
    use starknet::ClassHash;
    use starknet::ContractAddress;
    use starknet::contract_address_try_from_felt252;
    use option::OptionTrait; 

    #[storage]
    struct Storage {
    }

    // We use a constant for the contract_address to test the replace_class functionality
    const get_number_contract_address: felt252 = 1;

    #[external(v0)]
    impl GetNumberWrapper of super::IGetNumber<ContractState> {
        fn get_number(self: @ContractState) -> felt252 {
            let address = contract_address_try_from_felt252(get_number_contract_address).unwrap();
            GetNumberDispatcher {contract_address: address}.get_number()
        }

        fn upgrade(self: @ContractState, new_class_hash: ClassHash) {
            let address = contract_address_try_from_felt252(get_number_contract_address).unwrap();
            GetNumberDispatcher {contract_address: address}.upgrade(new_class_hash);
        }

        fn get_numbers_old_new(self: @ContractState, new_class_hash: ClassHash) -> (felt252, felt252){
            let address = contract_address_try_from_felt252(get_number_contract_address).unwrap();
            let old_number = GetNumberDispatcher {contract_address: address}.get_number();
            GetNumberDispatcher {contract_address: address}.upgrade(new_class_hash);
            let new_number = GetNumberDispatcher {contract_address: address}.get_number();
            (old_number, new_number)
        }
    }
}
