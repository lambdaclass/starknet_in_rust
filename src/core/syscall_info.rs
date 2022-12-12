use cairo_rs::serde::deserialize_program::*;
use std::fs;

pub fn program_json() {
    let path = "syscalls.json";
    let file =  fs::read_to_string(path).unwrap();
    let json : ProgramJson = serde_json::from_str(&file).unwrap();
    for identifier in json.identifiers {
        println!("");
        println!("{:?}", identifier);
    }
}