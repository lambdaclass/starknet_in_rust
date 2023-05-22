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
    fn square_root(n: felt252, math_class_hash: ClassHash) -> felt252 {
        MathLibraryDispatcher {class_hash: math_class_hash}.square_root(n)
    }
}