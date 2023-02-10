use reqwest::{Client, RequestBuilder};
use serde_json::json;

use crate::core::contract_address;

pub async fn get_contract_class(class_hash: &str) -> Result<(), reqwest::Error> {
    let client = Client::new();
    let request_body = json!({
        "jsonrpc": "2.0",
        "method": "starknet_getClass",
        "params": [
            {
                "block_hash": "0x0785b4aa83ed9ad6fadaf9a4ac445b7d05d170a5807bed2acf97ea0a934c2c14"
            },
            class_hash
        ],
        "id": 0
    });

    let request: RequestBuilder = client
        .post("http://localhost:8080")
        .header("Content-Type", "application/json")
        .body(serde_json::to_string(&request_body).unwrap());

    let response = request.send().await?;

    let response_text = response.text().await?;
    println!("{}", response_text);

    Ok(())
}

pub async fn get_class_hash_at(contract_address: &str) -> Result<(), reqwest::Error> {
    let client = Client::new();
    let request_body = json!({
        "jsonrpc": "2.0",
        "method": "starknet_getClass",
        "params": [
            {
                "block_hash": "0x0785b4aa83ed9ad6fadaf9a4ac445b7d05d170a5807bed2acf97ea0a934c2c14"
            },
            contract_address
        ],
        "id": 0
    });

    let request: RequestBuilder = client
        .post("http://localhost:8080")
        .header("Content-Type", "application/json")
        .body(serde_json::to_string(&request_body).unwrap());

    let response = request.send().await?;

    let response_text = response.text().await?;
    println!("{}", response_text);

    Ok(())
}

pub async fn get_nonce_at(contract_address: &str) -> Result<(), reqwest::Error> {
    let client = Client::new();
    let request_body = json!({
        "jsonrpc": "2.0",
        "method": "starknet_getClass",
        "params": [
            {
                "block_hash": "0x0785b4aa83ed9ad6fadaf9a4ac445b7d05d170a5807bed2acf97ea0a934c2c14"
            },
            contract_address
        ],
        "id": 0
    });

    let request: RequestBuilder = client
        .post("http://localhost:8080")
        .header("Content-Type", "application/json")
        .body(serde_json::to_string(&request_body).unwrap());

    let response = request.send().await?;

    let response_text = response.text().await?;
    println!("{}", response_text);

    Ok(())
}

pub async fn get_storage_at(contract_address: &str, key: &str) -> Result<(), reqwest::Error> {
    let client = Client::new();
    let request_body = json!({
        "jsonrpc": "2.0",
        "method": "starknet_getClass",
        "params": [
            {
                "block_hash": "0x0785b4aa83ed9ad6fadaf9a4ac445b7d05d170a5807bed2acf97ea0a934c2c14"
            },
            contract_address,
            key
        ],
        "id": 0
    });

    let request: RequestBuilder = client
        .post("http://localhost:8080")
        .header("Content-Type", "application/json")
        .body(serde_json::to_string(&request_body).unwrap());

    let response = request.send().await?;

    let response_text = response.text().await?;
    println!("{}", response_text);

    Ok(())
}