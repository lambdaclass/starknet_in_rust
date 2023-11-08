use clap::{Parser, Subcommand};
use rpc_state_reader::{
    execute_tx,
    rpc_state::{RpcChain, RpcTransactionReceipt, TransactionTrace},
};
use starknet_api::block::BlockNumber;
use starknet_in_rust::execution::TransactionExecutionInfo;

#[derive(Debug, Parser)]
#[command(about = "Replay is a tool for executing Starknet transactions.", long_about = None)]
struct ReplayCLI {
    #[command(subcommand)]
    subcommand: ReplayExecute,
}

#[derive(Subcommand, Debug)]
enum ReplayExecute {
    #[clap(about = "Execute a single transaction given a transaction hash.")]
    Tx {
        tx_hash: String,
        chain: String,
        block_number: u64,
    },
    #[clap(about = "Execute all the invoke transactions in a given block.")]
    Block { block_number: u64, chain: String },
    #[clap(about = "Execute all the invoke transactions in a given range of blocks.")]
    BlockRange {
        block_start: u64,
        block_end: u64,
        chain: String,
    },
}

fn main() {
    let cli = ReplayCLI::parse();

    match cli.subcommand {
        ReplayExecute::Tx {
            tx_hash,
            chain,
            block_number,
        } => {
            let rpc_chain: RpcChain = match chain.as_str() {
                "mainnet" => RpcChain::MainNet,
                "testnet" => RpcChain::TestNet,
                "testnet2" => RpcChain::TestNet2,
                _ => panic!("Invalid chain name"),
            };
            let block_number = BlockNumber(block_number);

            let (tx_info, trace, receipt) = execute_tx(&tx_hash, rpc_chain, block_number).unwrap();

            // TODO: Show all the data correctly
            let TransactionExecutionInfo {
                call_info,
                validate_info,
                fee_transfer_info,
                revert_error,
                actual_fee,
                ..
            } = tx_info;
            
            let sir_actual_fee = actual_fee;

            let TransactionTrace {
                validate_invocation,
                function_invocation,
                fee_transfer_invocation,
                ..
            } = trace;

            let RpcTransactionReceipt {
                actual_fee,
                execution_status,
                ..
            } = receipt;

            println!("Transaction hash: {}", tx_hash);
            println!("Block number: {}", block_number.0);
            println!("Chain: {}", chain);
            println!("[RPC] Execution status: {:?}", execution_status);
            println!("[RPC] Actual fee: {}", actual_fee);
            println!("[SIR] Actual fee: {:?}", sir_actual_fee);
        }
        ReplayExecute::Block {
            block_number,
            chain,
        } => {}
        ReplayExecute::BlockRange {
            block_start,
            block_end,
            chain,
        } => {

        }
    }
}
