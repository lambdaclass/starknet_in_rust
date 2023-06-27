#[starknet::interface]
trait Math<TContractState> {
    fn square_root(ref self: TContractState, n: felt252) -> felt252;
}

#[starknet::interface]
trait ISquareRoot<TContractState> {
        fn square_root(ref self: TContractState, n: felt252, math_class_hash: felt252) -> felt252;
}


#[starknet::contract]
mod SquareRoot {
    use super::MathDispatcherTrait;
    use super::MathDispatcher;
    use starknet::ClassHash;
    use option::OptionTrait;
    use starknet::contract_address_try_from_felt252;

    #[storage]
    struct Storage{
    }
    
    #[external(v0)]
    impl SquareRoot of super::ISquareRoot<ContractState> {
        
     fn square_root(ref self: ContractState, n: felt252, math_class_hash: felt252) -> felt252 {

         let address = contract_address_try_from_felt252(math_class_hash).unwrap();
         MathDispatcher {contract_address: address}.square_root(n)
     }
    }
}