// Ethereum gas usage constants; for more details, see
// page 27 in https://ethereum.github.io/yellowpaper/paper.pdf.

// Calldata.
pub(crate) const GAS_PER_MEMORY_ZERO_BYTE: usize = 4;
pub(crate) const GAS_PER_MEMORY_BYTE: usize = 16;
pub(crate) const WORD_WIDTH: usize = 32;
pub(crate) const GAS_PER_MEMORY_WORD: usize = GAS_PER_MEMORY_BYTE * WORD_WIDTH;

pub(crate) const GAS_PER_LOG_DATA_BYTE: usize = 8;
pub(crate) const GAS_PER_LOG_TOPIC: usize = 375;
pub(crate) const GAS_PER_LOG: usize = 375;
pub(crate) const GAS_PER_LOG_DATA_WORD: usize = GAS_PER_LOG_DATA_BYTE * WORD_WIDTH;
pub(crate) const GAS_PER_ZERO_TO_NONZERO_STORAGE_SET: usize = 20000;
pub(crate) const GAS_PER_COLD_STORAGE_ACCESS: usize = 2100;
pub(crate) const GAS_PER_NONZERO_TO_INT_STORAGE_SET: usize = 2900;
pub(crate) const GAS_PER_COUNTER_DECREASE: usize =
    GAS_PER_COLD_STORAGE_ACCESS + GAS_PER_NONZERO_TO_INT_STORAGE_SET;
pub(crate) const SHARP_ADDITIONAL_GAS_PER_MEMORY_WORD: usize = 100; //This value is not accurate.
pub(crate) const SHARP_GAS_PER_MEMORY_WORD: usize =
    GAS_PER_MEMORY_WORD + SHARP_ADDITIONAL_GAS_PER_MEMORY_WORD;

// Constants used to calculate discounts in onchain data cost calculation

// 10% discount for data availability.
pub(crate) const DISCOUNT_PER_DA_WORD: usize = (SHARP_GAS_PER_MEMORY_WORD * 10) / 100;
pub(crate) const SHARP_GAS_PER_DA_WORD: usize = SHARP_GAS_PER_MEMORY_WORD - DISCOUNT_PER_DA_WORD;

// For each modified contract, the expected non-zeros bytes in the second word are:
// 1 bytes for class hash flag; 2 for number of storage updates (up to 64K);
// 3 for nonce update (up to 16M).
const MODIFIED_CONTRACT_COST: usize =
    6 * GAS_PER_MEMORY_BYTE + (WORD_WIDTH - 6) * GAS_PER_MEMORY_ZERO_BYTE;
pub(crate) const MODIFIED_CONTRACT_DISCOUNT: usize = GAS_PER_MEMORY_WORD - MODIFIED_CONTRACT_COST;

// Up to balance of 8*(10**10) ETH.
pub(crate) const FEE_BALANCE_VALUE_COST: usize =
    12 * GAS_PER_MEMORY_BYTE + (WORD_WIDTH - 12) * GAS_PER_MEMORY_ZERO_BYTE;
