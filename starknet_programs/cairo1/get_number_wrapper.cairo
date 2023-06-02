use starknet::ClassHash;

#[abi]
trait GetNumber {

    #[view]
    fn get_number() -> felt252;

    #[external]
    fn upgrade(new_class_hash: ClassHash);
}

#[contract]
mod GetNumberWrapper {
    use super::GetNumberDispatcherTrait; 
    use super::GetNumberDispatcher;
    use starknet::ClassHash;
    use starknet::ContractAddress;
    use starknet::contract_address_try_from_felt252;
    use option::OptionTrait; 

    // We use a constant for the contract_address to test the replace_class functionality
    const get_number_contract_address: felt252 = 1;

    #[view]
    fn get_number() -> felt252 {
        let address = contract_address_try_from_felt252(get_number_contract_address).unwrap();
        GetNumberDispatcher {contract_address: address}.get_number()
    }

    #[external]
    fn upgrade(new_class_hash: ClassHash) {
        let address = contract_address_try_from_felt252(get_number_contract_address).unwrap();
        GetNumberDispatcher {contract_address: address}.upgrade(new_class_hash);
    }

    #[external]
    fn get_numbers_old_new(new_class_hash: ClassHash) -> (felt252, felt252){
        let address = contract_address_try_from_felt252(get_number_contract_address).unwrap();
        let old_number = GetNumberDispatcher {contract_address: address}.get_number();
        GetNumberDispatcher {contract_address: address}.upgrade(new_class_hash);
        let new_number = GetNumberDispatcher {contract_address: address}.get_number();
        (old_number, new_number)
    }
}
      
