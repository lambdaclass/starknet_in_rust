#![allow(unused)]
#![deny(warnings)]

use starknet_rs::core::syscall_info;

mod patricia_merkle_tree;

fn main() {
    let p = syscall_info::program_json().unwrap().identifiers;
    println!("{:?}", p);
}
