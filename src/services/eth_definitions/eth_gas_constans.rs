// Ethereum gas usage constants; for more details, see
// page 27 in https://ethereum.github.io/yellowpaper/paper.pdf.

pub(crate) const WORD_WIDTH: usize = 32;
pub(crate) const GAS_PER_MEMORY_BYTE: usize = 16;
pub(crate) const GAS_PER_LOG_DATA_BYTE: usize = 8;
pub(crate) const GAS_PER_LOG_TOPIC: usize = 375;
pub(crate) const GAS_PER_LOG: usize = 375;
pub(crate) const GAS_PER_LOG_DATA_WORD: usize = GAS_PER_LOG_DATA_BYTE * WORD_WIDTH;
pub(crate) const GAS_PER_MEMORY_WORD: usize = GAS_PER_MEMORY_BYTE * WORD_WIDTH;
pub(crate) const GAS_PER_ZERO_TO_NONZERO_STORAGE_SET: usize = 20000;
pub(crate) const GAS_PER_COLD_STORAGE_ACCESS: usize = 2100;
pub(crate) const GAS_PER_NONZERO_TO_INT_STORAGE_SET: usize = 2900;
pub(crate) const GAS_PER_COUNTER_DECREASE: usize =
    GAS_PER_COLD_STORAGE_ACCESS + GAS_PER_NONZERO_TO_INT_STORAGE_SET;
pub(crate) const SHARP_ADDITIONAL_GAS_PER_MEMORY_WORD: usize = 100; //This value is not accurate.
pub(crate) const SHARP_GAS_PER_MEMORY_WORD: usize =
    GAS_PER_MEMORY_WORD + SHARP_ADDITIONAL_GAS_PER_MEMORY_WORD;
