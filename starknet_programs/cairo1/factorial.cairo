#[contract]
mod Factorial {

    #[external]
    fn factorial(n: felt252) -> felt252 {
        match n {
            0 => 1,
            _ => n * factorial(n-1),
        }
    }
}
