// Extracted from https://book.starknet.io/chapter_7/hello_account.html

// Import necessary modules
#[account_contract]
mod HelloAccount {
    use starknet::ContractAddress;
    use core::felt252;
    use array::ArrayTrait;
    use array::SpanTrait;

    // Validate deployment of the contract.
    // Returns starknet::VALIDATED to confirm successful validation.
    #[external]
    fn __validate_deploy__(
        class_hash: felt252, contract_address_salt: felt252, public_key_: felt252
    ) -> felt252 {
        starknet::VALIDATED
    }

    // Validate declaration of transactions using this Account.
    // This function enforces that transactions now require accounts to pay fees.
    // Returns starknet::VALIDATED to confirm successful validation.
    #[external]
    fn __validate_declare__(class_hash: felt252) -> felt252 {
        starknet::VALIDATED
    }

    // Validate transaction before execution.
    // This function is called by the account contract upon receiving a transaction.
    // If the validation is successful, it returns starknet::VALIDATED.
    #[external]
    fn __validate__(
        contract_address: ContractAddress, entry_point_selector: felt252, calldata: Array::<felt252>
    ) -> felt252 {
        starknet::VALIDATED
    }

    // Execute transaction.
    // If the '__validate__' function is successful, this '__execute__' function will be called.
    // It forwards the call to the target contract using starknet::call_contract_syscall.
    #[external]
    #[raw_output]
    fn __execute__(
        contract_address: ContractAddress, entry_point_selector: felt252, calldata: Array::<felt252>
    ) -> Span::<felt252> {
        starknet::call_contract_syscall(
            address: contract_address,
            entry_point_selector: entry_point_selector,
            calldata: calldata.span()
        ).unwrap_syscall()
    }
}
