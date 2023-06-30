#[starknet::interface]
trait IEventTest<TContractState> {
    fn trigger_events(ref self: TContractState) -> ();
}

#[starknet::contract]
mod EventTest {
    #[storage]
    struct Storage {
    }

    #[event]
    #[derive(Drop, starknet::Event)]
    enum Event {
        EmitEvent: EmitEvent
    }

    #[derive(Drop, starknet::Event)]
    struct EmitEvent {
        n: felt252
    }


    #[external(v0)]
    impl EventTest of super::IEventTest<ContractState> {
        fn trigger_events(ref self: ContractState) -> () {
            self.emit(Event::EmitEvent(EmitEvent { n: 1 }));
            self.emit(Event::EmitEvent(EmitEvent { n: 2 }));
            self.emit(Event::EmitEvent(EmitEvent { n: 3 }));
        }
    }
}
