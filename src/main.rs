use starknet_rs::core::syscall_info;
fn main() {
    let p = syscall_info::program_json().unwrap().identifiers;
    println!("{:?}", p);
}
