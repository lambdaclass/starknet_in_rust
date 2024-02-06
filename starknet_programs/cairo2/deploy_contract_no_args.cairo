#[starknet::interface]
trait IDeploy<TContractState> {
    fn deploy_no_args(self: @TContractState, class_hash: starknet::class_hash::ClassHash) -> felt252;
}

#[starknet::contract]
mod Deploy {
    use array::{Array, ArrayTrait, Span, SpanTrait};
    use starknet::{syscalls::deploy_syscall, contract_address_to_felt252, class_hash::ClassHash};
    use result::ResultTrait;


    #[storage]
    struct Storage {
    }

    #[external(v0)]
    impl Deploy of super::IDeploy<ContractState> {
        fn deploy_no_args(self: @ContractState, class_hash: ClassHash) -> felt252 {
            let calldata = ArrayTrait::new();
            match deploy_syscall(class_hash, 0, calldata.span(), false) {
                Result::Ok((addr, _)) => contract_address_to_felt252(addr),
                Result::Err(revert_reason) => *revert_reason.span().at(0),
            }
        }
    }
}
