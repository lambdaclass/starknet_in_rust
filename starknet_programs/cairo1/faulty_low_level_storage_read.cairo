#[contract]
mod ReadStorage {
    use array::{Array, ArrayTrait, Span, SpanTrait};
    use starknet::{syscalls::storage_read_syscall, storage_access::{StorageAddress, storage_address_try_from_felt252}};
    use result::ResultTrait;
    use option::OptionTrait;

    #[external]
    fn read_storage() -> felt252 {
        let address = storage_address_try_from_felt252(1).unwrap();
        match storage_read_syscall(3, address) {
            Result::Ok(value) => value,
            Result::Err(revert_reason) => *revert_reason.span().at(0),
        }

    }
}
