#[contract]
mod Math {
    use integer::u128_sqrt;
    use core::traits::Into;
    use traits::TryInto;
    use option::OptionTrait;

    #[external]
    fn square_root(n: felt252) -> felt252 {
        assert( 0 == 1 , 'Unimplemented');
        0
    }
}