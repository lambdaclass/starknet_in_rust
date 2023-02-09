use felt::Felt;
use lazy_static::lazy_static;
use num_traits::Num;
use std::{any::Any, collections::HashMap};

pub type AbiType = Vec<HashMap<String, String>>;

lazy_static! {
    pub static ref VALIDATE_ENTRY_POINT_SELECTOR: Felt = Felt::from_str_radix(
        "626969833899987279399947180575486623810258720106406659648356883742278317941",
        10,
    )
    .unwrap();
}
