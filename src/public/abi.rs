use std::{any::Any, collections::HashMap};

pub type AbiType = Vec<HashMap<String, Box<dyn Any>>>;
