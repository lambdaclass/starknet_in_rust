use felt::Felt252;
use lazy_static::lazy_static;
use num_traits::Num;
use std::collections::HashMap;

pub type AbiType = Vec<HashMap<String, String>>;

lazy_static! {
    pub static ref VALIDATE_ENTRY_POINT_SELECTOR: Felt252 = Felt252::from_str_radix(
        "626969833899987279399947180575486623810258720106406659648356883742278317941",
        10,
    )
    .unwrap();
    pub static ref CONSTRUCTOR_ENTRY_POINT_SELECTOR: Felt252 = Felt252::from_str_radix(
        "1159040026212278395030414237414753050475174923702621880048416706425641521556",
        10,
    )
    .unwrap();
}
