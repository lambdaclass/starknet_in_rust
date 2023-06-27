#[starknet::interface]
trait IMath<TContractState> {
    fn square_root(ref self: TContractState, n: felt252) -> felt252;
}

#[starknet::interface]
trait ISquareRoot<TContractState> {
        fn square_root(ref self: TContractState, n: felt252, math_class_hash: starknet::class_hash::ClassHash) -> felt252;
}

#[starknet::contract]
mod SquareRoot {
    use super::MathDispatcherTrait; 
    use super::MathLibraryDispatcher;
    use starknet::ClassHash;

    #[storage]
    struct Storage{
    }
    
    #[external(v0)]
    impl SquareRoot of super::ISquareRoot<ContractState> {
        
        fn square_root(ref self: ContractState, n: felt252, math_class_hash: ClassHash) -> felt252 {
            MathLibraryDispatcher {class_hash: math_class_hash}.square_root(n)
        }
    }
}