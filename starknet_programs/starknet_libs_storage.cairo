%lang starknet
from starkware.starknet.common.storage import normalize_address

@external
func normalize{range_check_ptr}(address: felt) -> (res: felt) {
     return normalize_address(address);
}
