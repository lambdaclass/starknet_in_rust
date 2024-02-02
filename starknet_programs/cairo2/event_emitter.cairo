#[starknet::contract]
mod EventTest {
    use starknet::syscalls::emit_event_syscall;

    #[storage]
    struct Storage {
        balance: felt252,
    }

    #[event]
    #[derive(Drop, starknet::Event)]
    enum Event {
        EmitEvent: EmitEvent
    }

    #[derive(Drop, starknet::Event)]
    struct EmitEvent {
        n: u128, 
    }

    #[abi(embed_v0)]
    fn trigger_event(ref self: ContractState) -> felt252 {
        let mut keys = ArrayTrait::new();
        keys.append('n');
        let mut values = ArrayTrait::new();
        values.append(1);
        emit_event_syscall(keys.span(), values.span()).unwrap();
        1234
    }
}
