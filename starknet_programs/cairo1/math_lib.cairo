#[contract]
mod Math {
    use integer::u128_sqrt;
    use core::traits::Into;
    use traits::TryInto;
    use option::OptionTrait;

    #[external]
    fn square_root(n: felt252) -> felt252 {
        let n_u128: u128 = n.try_into().unwrap();
        let n_u64: u64 = u128_sqrt(n_u128);
        n_u64.into()
    }
}