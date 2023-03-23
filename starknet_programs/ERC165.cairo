// SPDX-License-Identifier: MIT
// OpenZeppelin Contracts for Cairo v0.6.1 (introspection/erc165/library.cairo)

%lang starknet

from starkware.cairo.common.cairo_builtins import HashBuiltin
from starkware.cairo.common.math import assert_not_equal
from starkware.cairo.common.bool import FALSE

from openzeppelin.utils.constants.library import INVALID_ID, IERC165_ID

@storage_var
func ERC165_supported_interfaces(interface_id: felt) -> (is_supported: felt) {
}

@external
func supportsInterface{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr}(
    interface_id: felt
) -> (success: felt) {
    return (success=FALSE);
}
