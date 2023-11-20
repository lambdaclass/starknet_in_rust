use starknet::ClassHash;

#[starknet::interface]
trait Math<TContractState> {
    fn square_root(self: @TContractState, n: felt252) -> felt252;
}

#[starknet::interface]
trait ISquareRoot<TContractState> {
    fn square_root(self: @TContractState, n: felt252, math_class_hash: ClassHash, n_iterations: u32) -> felt252;
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
        fn square_root(self: @ContractState, n: felt252, math_class_hash: ClassHash, n_iterations: u32) -> felt252 {
            square_root_recursive_inner(n, math_class_hash, n_iterations)
        }
    }

    fn square_root_recursive_inner(n: felt252, math_class_hash: ClassHash, n_iterations: u32) -> felt252 {
        if n_iterations == 0 {
            return n;
        }
        square_root_recursive_inner(MathLibraryDispatcher {class_hash: math_class_hash}.square_root(n), math_class_hash, n_iterations - 1)
    }
}
