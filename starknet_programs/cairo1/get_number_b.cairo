#[contract]
mod GetNumber {
    use core::starknet::class_hash::ClassHash;
    use core::starknet::replace_class_syscall;

    #[view]
    fn get_number() -> felt252 {
        17
    }

    #[external]
    fn upgrade(new_class_hash: ClassHash)  {
        replace_class_syscall(new_class_hash);
    }
}
