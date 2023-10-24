#[abi]
trait Math {
    #[external]
    fn square_root(n: felt252) -> felt252;
}

#[contract]
mod SquareRoot {
    use super::MathDispatcherTrait; 
    use super::MathLibraryDispatcher;
    use starknet::ClassHash;

    #[external]
    fn square_root_recursive(n: felt252, math_class_hash: ClassHash, n_iterations: u32) -> felt252 {
        square_root_recursive_inner(n, math_class_hash, n_iterations)
    }

    fn square_root_recursive_inner(n: felt252, math_class_hash: ClassHash, n_iterations: u32) -> felt252 {
        if n_iterations == 0 {
            return n;
        }
        square_root_recursive_inner(MathLibraryDispatcher {class_hash: math_class_hash}.square_root(n), math_class_hash, n_iterations - 1)
    }
}
