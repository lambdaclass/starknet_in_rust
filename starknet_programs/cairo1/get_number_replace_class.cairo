#[abi]
trait GetNumber {
    #[view]
    fn get_number() -> felt252;

    #[external]
    fn upgrade(new_class_hash: ClassHash);
}

#[contract]
mod GetNumberWrapper
    use super::GetNumberDispatcherTrait; 
    use super::GetNumberDispatcher;
    use starknet::ContractAddress;

    // We use a constant for the class_hash to test the replace_class functionality
    const get_number_class_hash = ClassHash(2);

    #[view]
    fn get_number() -> felt252 {
        GetNumberLibDispatcher {class_hash: get_number_class_hash}.get_number()
    }

    #[external]
    fn upgrade(new_class_hash: ClassHash) {
        GetNumberDispatcher {class_hash: get_number_class_hash}.upgrade(new_class_hash);
    }
}
      
