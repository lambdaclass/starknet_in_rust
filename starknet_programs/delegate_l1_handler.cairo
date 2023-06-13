%lang starknet

from starkware.cairo.common.alloc import alloc
from starkware.cairo.common.cairo_builtins import HashBuiltin
from starkware.starknet.common.syscalls import (
    DELEGATE_L1_HANDLER_SELECTOR, CallContractRequest, CallContract
)

// Address set in test for contract get_number.cairo
const CONTRACT_ADDRESS = 1;

func delegate_l1_handler{syscall_ptr: felt*}(
    contract_address: felt, function_selector: felt, calldata_size: felt, calldata: felt*
) -> (retdata_size: felt, retdata: felt*) {
    let syscall = [cast(syscall_ptr, CallContract*)];
    assert syscall.request = CallContractRequest(
        selector=DELEGATE_L1_HANDLER_SELECTOR,
        contract_address=contract_address,
        function_selector=function_selector,
        calldata_size=calldata_size,
        calldata=calldata,
    );
    %{ syscall_handler.delegate_l1_handler(segments=segments, syscall_ptr=ids.syscall_ptr) %}
    let response = syscall.response;

    let syscall_ptr = syscall_ptr + CallContract.SIZE;
    return (retdata_size=response.retdata_size, retdata=response.retdata);
}

@external
func test_delegate_l1_handler{
    syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr: felt
}() {
    let (calldata) = alloc();
    let (retdata_size, retdata) = delegate_l1_handler(
        contract_address=CONTRACT_ADDRESS,
        // function_selector=sn_keccak('get_number'),
        function_selector=0x23180acc053dfb2dbc82a0da33515906d37498b42f34ee4ed308f9d5fb51b6c,
        calldata_size=0,
        calldata=calldata,
    );
    assert retdata_size = 1;
    return ();
}
