#[contract]
mod SendMessageToL1 {

    use starknet::syscalls::send_message_to_l1_syscall;

    #[external]
    fn send_msg(to_address: felt252, payload: Span<felt252>) {
        send_message_to_l1_syscall(to_address, payload);
    }
}
