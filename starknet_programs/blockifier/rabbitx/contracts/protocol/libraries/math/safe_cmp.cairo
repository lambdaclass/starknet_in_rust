from starkware.cairo.common.math_cmp import is_le_felt
from starkware.cairo.common.math import assert_le_felt, assert_lt_felt
from starkware.cairo.common.bool import FALSE, TRUE
from blockifier.rabbitx.contracts.protocol.libraries.helpers.bool_cmp import BoolCmp
from blockifier.rabbitx.contracts.protocol.libraries.helpers.constants import (
    MAX_SIGNED_FELT,
    MIN_SIGNED_FELT,
)

// @notice Function checks if the a < b. Interprets a, b in range [0, P)
// @dev Internal function meant to only be used by functions of SafeCmp library
// @param a Unsigned felt integer
// @param b Unsigned felt integer
// @returns res Bool felt indicating if a < b
func _is_lt_felt{range_check_ptr}(a: felt, b: felt) -> (res: felt) {
    if (a == b) {
        return (FALSE,);
    }
    return (is_le_felt(a, b),);
}

// @notice Library to safely compare felts interpreted as unsigned or signed integers.
//
//         Motivation:
//         Cairo felts represent signed or unsigned integers.
//         To compare unsigned integers developers can use: is_le_felt, assert_le_felt from math_cmp and math library
//         However, currently there is no safe way to compare felts interpreted as signed integers.
//         Developer when working with signed integers tend to use functions: is_le, assert_le, is_nn, assert_nn.
//         This is not safe, because those functions work in range [0, 2**128) and should only be used with context of Uint256 type (with low and high members)
//         Functions provided in this library allow for safe work with felts interpreted as signed and unsigned integers, outside of Uint256 context.
//
// @author Nethermind
namespace SafeCmp {
    //
    //
    // UNSIGNED FELTS
    //
    //

    // @notice Checks if the a <= b. Interprets a, b in range [0, P)
    // @param a Unsigned felt integer
    // @param b Unsigned felt integer
    // @returns res Bool felt indicating if a <= b
    func is_le_unsigned{range_check_ptr}(a: felt, b: felt) -> (res: felt) {
        return (is_le_felt(a, b),);
    }

    // @notice Checks if the a < b. Interprets a, b in range [0, P)
    // @param a Unsigned felt integer
    // @param b Unsigned felt integer
    // @returns res Bool felt indicating if a < b
    func is_lt_unsigned{range_check_ptr}(a: felt, b: felt) -> (res: felt) {
        return _is_lt_felt(a, b);
    }

    // @notice Checks if the vale is in range [low, high). Interprets value, low, high in range [0, P)
    // @param value Unsigned felt integer, checked if is in range
    // @param low Unsigned felt integer, lower bound of the range
    // @param high Unsigned felt integer, upper bound of the range
    // @returns res Bool felt indicating if low <= value < high
    func is_in_range_unsigned{range_check_ptr}(value: felt, low: felt, high: felt) -> (res: felt) {
        alloc_locals;
        with_attr error_message("Range definition error: low >= high") {
            let (check) = _is_lt_felt(low, high);
            assert check = TRUE;
        }
        let ok_low = is_le_felt(low, value);
        let (ok_high) = _is_lt_felt(value, high);
        let (res) = BoolCmp.both(ok_low, ok_high);
        return (res,);
    }

    // @notice Asserts that a <= b. Interprets a, b in range [0, P)
    // @param a Unsigned felt integer
    // @param b Unsigned felt integer
    func assert_le_unsigned{range_check_ptr}(a: felt, b: felt) {
        assert_le_felt(a, b);
        return ();
    }

    // @notice Asserts that a < b. Interprets a, b in range [0, P)
    // @param a Unsigned felt integer
    // @param b Unsigned felt integer
    func assert_lt_unsigned{range_check_ptr}(a: felt, b: felt) {
        assert_lt_felt(a, b);
        return ();
    }

    // @notice Asserts that the value is in range [low, high). Interprets value, low, high in range [0, P)
    // @param value Unsigned felt integer, checked if is in range
    // @param low Unsigned felt integer, lower bound of the range
    // @param high Unsigned felt integer, upper bound of the range
    func assert_in_range_unsigned{range_check_ptr}(value: felt, low: felt, high: felt) {
        alloc_locals;
        with_attr error_message("Range definition error: low >= high") {
            let (check) = _is_lt_felt(low, high);
            assert check = TRUE;
        }
        let ok_low = is_le_felt(low, value);
        let (ok_high) = _is_lt_felt(value, high);
        assert ok_low * ok_high = TRUE;
        return ();
    }

    //
    //
    // SIGNED FELTS
    //
    //

    // @notice Checks if the value is non-negative integer, i.e. 0 <= value < floor(P/2) + 1. Interprets a in range [floor(-P/2), floor(P/2)]
    // @dev Note that floor(-P/2) is equal to floor(P/2) + 1. If felt is signed, then negative numbers are [floor(P/2)+1, P-1]
    // @param a Signed felt integer
    // @returns res Bool felt indicating if 0 <= value < floor(P/2) + 1 (Recall : floor(P/2) = (P-1)/2)
    func is_nn_signed{range_check_ptr}(value: felt) -> (res: felt) {
        return _is_lt_felt(value, MIN_SIGNED_FELT);
    }

    // @notice Checks if the a <= b. Interprets a, b in range [floor(-P/2), floor(P/2)] (Recall : floor(P/2) = (P-1)/2)
    // @dev Note that floor(-P/2) is equal to floor(P/2) + 1. If felt is signed, then negative numbers are [floor(P/2)+1, P-1], and non-negative [0(P), floor(P/2)]
    // @param a Signed felt integer
    // @param b Signed felt integer
    // @returns res Bool felt indicating if a <= b
    func is_le_signed{range_check_ptr}(a: felt, b: felt) -> (res: felt) {
        return (is_le_felt(a + MAX_SIGNED_FELT, b + MAX_SIGNED_FELT),);
    }

    // @notice Checks if the a < b. Interprets a, b in range [floor(-P/2), floor(P/2)]
    // @dev Note that floor(-P/2) is equal to floor(P/2) + 1. If felt is signed, then negative numbers are [floor(P/2)+1, P-1], and non-negative [P, floor(P/2)]
    // @param a Signed felt integer
    // @param b Signed felt integer
    // @returns res Bool felt indicating if a < b
    func is_lt_signed{range_check_ptr}(a: felt, b: felt) -> (res: felt) {
        return _is_lt_felt(a + MAX_SIGNED_FELT, b + MAX_SIGNED_FELT);
    }

    // @notice Checks if the [low, high). Interprets value, low, high in range [floor(-P/2), floor(P/2)]
    // @dev Note that floor(-P/2) is equal to floor(P/2) + 1. If felt is signed, then negative numbers are [floor(P/2)+1, P-1], and non-negative [P, floor(P/2)]
    // @param value Signed felt integer, checked if is in range
    // @param low Signed felt integer, lower bound of the range
    // @param high Signed felt integer, upper bound of the range
    // @returns res Bool felt indicating if value is in [low, high) range
    func is_in_range_signed{range_check_ptr}(value: felt, low: felt, high: felt) -> (res: felt) {
        return is_in_range_unsigned(
            value + MAX_SIGNED_FELT, low + MAX_SIGNED_FELT, high + MAX_SIGNED_FELT
        );
    }

    // @notice Asserts that a is non-negative integer, i.e. 0 <= a < floor(P/2) + 1. Interprets a in range [floor(-P/2), floor(P/2)]
    // @dev Note that floor(-P/2) is equal to floor(P/2) + 1. If felt is signed, then negative numbers are [floor(P/2)+1, P-1]
    // @param a Signed felt integer
    func assert_nn_signed{range_check_ptr}(value: felt) {
        assert_lt_felt(value, MIN_SIGNED_FELT);
        return ();
    }

    // @notice Asserts that a <= b. Interprets a, b in range [floor(-P/2), floor(P/2)]
    // @dev Note that floor(-P/2) is equal to floor(P/2) + 1. If felt is signed, then negative numbers are [floor(P/2)+1, P-1], and non-negative [P, floor(P/2)]
    // @param a Signed felt integer
    // @param b Signed felt integer
    func assert_le_signed{range_check_ptr}(a: felt, b: felt) {
        assert_le_felt(a + MAX_SIGNED_FELT, b + MAX_SIGNED_FELT);
        return ();
    }

    // @notice Asserts that a < b. Interprets a, b in range [floor(-P/2), floor(P/2)]
    // @dev Note that floor(-P/2) is equal to floor(P/2) + 1. If felt is signed, then negative numbers are [floor(P/2)+1, P-1], and non-negative [P, floor(P/2)]
    // @param a Signed felt integer
    // @param b Signed felt integer
    func assert_lt_signed{range_check_ptr}(a: felt, b: felt) {
        assert_lt_felt(a + MAX_SIGNED_FELT, b + MAX_SIGNED_FELT);
        return ();
    }

    // @notice Asserts that the value is in [low, high). Interprets value, low, high in range [floor(-P/2), floor(P/2)]
    // @dev Note that floor(-P/2) is equal to floor(P/2) + 1. If felt is signed, then negative numbers are [floor(P/2)+1, P-1], and non-negative [P, floor(P/2)]
    // @param value Signed felt integer, checked if is in range
    // @param low Signed felt integer, lower bound of the range
    // @param high Signed felt integer, upper bound of the range
    func assert_in_range_signed{range_check_ptr}(value: felt, low: felt, high: felt) {
        assert_in_range_unsigned(
            value + MAX_SIGNED_FELT, low + MAX_SIGNED_FELT, high + MAX_SIGNED_FELT
        );
        return ();
    }
}
