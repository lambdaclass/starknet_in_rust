from starkware.cairo.common.uint256 import Uint256
from blockifier.rabbitx.contracts.protocol.libraries.types.data_types import DataTypes

const UINT128_MAX = 2 ** 128 - 1;
const INITIALIZE_SELECTOR = 215307247182100370520050591091822763712463273430149262739280891880522753123;

// P - the prime number defined in Cairo documentation. Every artithmetic operation is done with mod P.
// NOTE: This number shouldn't change for StartkNet, but if you are using Cairo with other P, please adjust this number to your needs.
const CAIRO_FIELD_ORDER = 2 ** 251 + 17 * 2 ** 192 + 1;  // 3618502788666131213697322783095070105623107215331596699973092056135872020481 == 0

// MAX_UNSIGNED_FELT
const MAX_UNSIGNED_FELT = CAIRO_FIELD_ORDER - 1;

// MAX_SIGNED_FELT
const MAX_SIGNED_FELT = (CAIRO_FIELD_ORDER - 1) / 2;

// MIN_SIGNED_FELT - the lowest number possible in Cairo if felts are interpreted as signed integers.
// (Recall : floor(P/2) = (P-1)/2)
// (P-1/2) is done to be able to express floor(P/2) (no floor function in Cairo)
// +1 is added, because (P-1/2): highest signed integer and (P-1/2)+1: lowest signed integer
const MIN_SIGNED_FELT = MAX_SIGNED_FELT + 1;  // as signed: -1809251394333065606848661391547535052811553607665798349986546028067936010240 or as unsigned: 1809251394333065606848661391547535052811553607665798349986546028067936010241

func empty_reserve_configuration() -> (res: DataTypes.ReserveConfiguration) {
    return (DataTypes.ReserveConfiguration(0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0),);
}

func empty_reserve_data() -> (res: DataTypes.ReserveData) {
    let (empty_config) = empty_reserve_configuration();
    return (DataTypes.ReserveData(empty_config, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0),);
}

func uint256_max() -> (max: Uint256) {
    return (Uint256(UINT128_MAX, UINT128_MAX),);
}
