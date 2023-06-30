#[starknet::contract]
mod FailingConstructor {
    #[storage]
    struct Storage {
    }

    #[constructor]
    fn constructor(ref self: ContractState) {
        assert( 1 == 0 , 'Oops');
    }
}
