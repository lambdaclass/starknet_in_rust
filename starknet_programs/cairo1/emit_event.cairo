#[contract]
mod Event {

    #[event]
    fn EmitEvent(n: felt252){}

    #[external]
    fn trigger_events() {
        EmitEvent(1);
        EmitEvent(2);
        EmitEvent(3);
    }
}
