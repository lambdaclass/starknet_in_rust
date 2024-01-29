use std::{
    io::{BufRead, BufReader},
    path::Path,
    process::{Child, Stdio},
};

use cairo_lang_sierra::program::{Program, VersionedProgram};
use cairo_vm::Felt252 as Felt;
use ipc_channel::ipc::{IpcOneShotServer, IpcReceiver, IpcSender};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use cairo_native::{
    execution_result::ContractExecutionResult,
    starknet::{ExecutionInfo, StarkNetSyscallHandler, SyscallResult},
};
use thiserror::Error;

use crate::utils::ClassHash;

#[derive(Debug, Error)]
pub enum SandboxError {
    #[error("ipc bincode error: {0}")]
    IpcBincodeError(#[from] ipc_channel::Error),
    #[error("ipc error: {0}")]
    IpcError(#[from] ipc_channel::ipc::IpcError),
    #[error("serializer error {0:?}")]
    SerializeError(#[from] serde_json::Error),
}

#[allow(clippy::large_enum_variant)]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Message {
    ExecuteJIT {
        id: Uuid,
        class_hash: ClassHash,
        program: VersionedProgram,
        inputs: Vec<Felt>,
        function_idx: usize,
        gas: Option<u128>,
    },
    ExecutionResult {
        id: Uuid,
        result: ContractExecutionResult,
    },
    Ack(Uuid),
    Ping,
    Kill,
    SyscallRequest(SyscallRequest),
    SyscallAnswer(SyscallAnswer),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SyscallRequest {
    GetBlockHash {
        block_number: u64,
        gas: u128,
    },
    GetExecutionInfo {
        gas: u128,
    },
    Deploy {
        class_hash: Felt,
        contract_address_salt: Felt,
        calldata: Vec<Felt>,
        deploy_from_zero: bool,
        gas: u128,
    },
    ReplaceClass {
        class_hash: Felt,
        gas: u128,
    },
    LibraryCall {
        class_hash: Felt,
        function_selector: Felt,
        calldata: Vec<Felt>,
        gas: u128,
    },
    CallContract {
        address: Felt,
        entry_point_selector: Felt,
        calldata: Vec<Felt>,
        gas: u128,
    },
    EmitEvent {
        keys: Vec<Felt>,
        data: Vec<Felt>,
        gas: u128,
    },
    SendMessageToL1 {
        to_address: Felt,
        payload: Vec<Felt>,
        gas: u128,
    },
    Keccak {
        input: Vec<u64>,
        gas: u128,
    },
    StorageRead {
        address_domain: u32,
        address: Felt,
        gas: u128,
    },
    StorageWrite {
        address_domain: u32,
        address: Felt,
        value: Felt,
        gas: u128,
    },
}

#[allow(clippy::large_enum_variant)]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SyscallAnswer {
    GetBlockHash {
        result: SyscallResult<Felt>,
        remaining_gas: u128,
    },
    GetExecutionInfo {
        result: SyscallResult<ExecutionInfo>,
        remaining_gas: u128,
    },
    Deploy {
        result: SyscallResult<(Felt, Vec<Felt>)>,
        remaining_gas: u128,
    },
    ReplaceClass {
        result: SyscallResult<()>,
        remaining_gas: u128,
    },
    LibraryCall {
        result: SyscallResult<Vec<Felt>>,
        remaining_gas: u128,
    },
    CallContract {
        result: SyscallResult<Vec<Felt>>,
        remaining_gas: u128,
    },
    StorageRead {
        result: SyscallResult<Felt>,
        remaining_gas: u128,
    },
    StorageWrite {
        result: SyscallResult<()>,
        remaining_gas: u128,
    },
    EmitEvent {
        result: SyscallResult<()>,
        remaining_gas: u128,
    },
    SendMessageToL1 {
        result: SyscallResult<()>,
        remaining_gas: u128,
    },
    Keccak {
        result: SyscallResult<cairo_native::starknet::U256>,
        remaining_gas: u128,
    },
}

impl Message {
    pub fn serialize(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string(self)
    }

    pub fn deserialize(value: &str) -> Result<Self, serde_json::Error> {
        serde_json::from_str(value)
    }

    pub fn wrap(&self) -> Result<WrappedMessage, serde_json::Error> {
        Ok(WrappedMessage::Message(self.serialize()?))
    }
}

#[derive(Debug, Serialize, Deserialize, PartialEq)]
pub enum WrappedMessage {
    // ipc-channel uses bincode and doesnt support serializing Vecs
    // so we serialize it to a json string first and pass it as a string.
    Message(String),
}

impl WrappedMessage {
    pub fn to_msg(self) -> Result<Message, serde_json::Error> {
        match self {
            WrappedMessage::Message(msg) => Message::deserialize(&msg),
        }
    }
}

#[derive(Debug)]
pub struct IsolatedExecutor {
    pub proc: Child,
    sender: IpcSender<WrappedMessage>,
    receiver: IpcReceiver<WrappedMessage>,
}

impl IsolatedExecutor {
    // "target/debug/cairo-executor"
    pub fn new(executor_path: &Path) -> Result<Self, std::io::Error> {
        let (server, server_name) = IpcOneShotServer::new().unwrap();
        tracing::debug!("creating executor with: {:?}", executor_path);

        let mut cmd = std::process::Command::new(executor_path);
        cmd.stdout(Stdio::piped());
        let mut proc = cmd.arg(server_name).spawn()?;
        let stdout = proc.stdout.take().unwrap();
        let mut stdout = BufReader::new(stdout);
        let mut client_name = String::new();
        stdout.read_line(&mut client_name)?;

        // first we accept the connection
        let (receiver, msg) = server.accept().expect("failed to accept receiver");
        tracing::debug!("accepted receiver {receiver:?} with msg {msg:?}");
        // then we connect
        tracing::debug!("connecting to {client_name}");
        let sender = IpcSender::connect(client_name.trim().to_string()).expect("failed to connect");
        sender.send(Message::Ping.wrap()?).unwrap();

        Ok(Self {
            proc,
            sender,
            receiver,
        })
    }

    pub fn run_program(
        &self,
        class_hash: ClassHash,
        program: Program,
        inputs: Vec<Felt>,
        gas: Option<u128>,
        function_idx: usize,
        handler: &mut impl StarkNetSyscallHandler,
    ) -> Result<ContractExecutionResult, SandboxError> {
        tracing::debug!("running program");
        let id = Uuid::new_v4();

        let msg = Message::ExecuteJIT {
            id,
            class_hash,
            program: program.into_artifact(),
            inputs,
            gas,
            function_idx,
        };
        self.sender.send(msg.wrap()?)?;

        loop {
            let msg = self.receiver.recv()?.to_msg()?;
            match msg {
                Message::ExecuteJIT { .. } => unreachable!(),
                Message::ExecutionResult {
                    id: recv_id,
                    result,
                } => {
                    assert_eq!(recv_id, id, "id mismatch");
                    return Ok(result);
                }
                Message::Ack(recv_id) => {
                    assert_eq!(recv_id, id, "id mismatch");
                }
                Message::Ping => unreachable!(),
                Message::Kill => todo!(),
                Message::SyscallRequest(request) => match request {
                    SyscallRequest::GetBlockHash {
                        block_number,
                        mut gas,
                    } => {
                        let result = handler.get_block_hash(block_number, &mut gas);
                        self.sender.send(
                            Message::SyscallAnswer(SyscallAnswer::GetBlockHash {
                                result,
                                remaining_gas: gas,
                            })
                            .wrap()?,
                        )?;
                    }
                    SyscallRequest::GetExecutionInfo { mut gas } => {
                        let result = handler.get_execution_info(&mut gas);
                        self.sender.send(
                            Message::SyscallAnswer(SyscallAnswer::GetExecutionInfo {
                                result,
                                remaining_gas: gas,
                            })
                            .wrap()?,
                        )?;
                    }
                    SyscallRequest::StorageRead {
                        address_domain,
                        address,
                        mut gas,
                    } => {
                        let result = handler.storage_read(address_domain, address, &mut gas);
                        self.sender.send(
                            Message::SyscallAnswer(SyscallAnswer::StorageRead {
                                result,
                                remaining_gas: gas,
                            })
                            .wrap()?,
                        )?;
                    }
                    SyscallRequest::StorageWrite {
                        address_domain,
                        address,
                        value,
                        mut gas,
                    } => {
                        let result =
                            handler.storage_write(address_domain, address, value, &mut gas);
                        self.sender.send(
                            Message::SyscallAnswer(SyscallAnswer::StorageWrite {
                                result,
                                remaining_gas: gas,
                            })
                            .wrap()?,
                        )?;
                    }
                    SyscallRequest::Deploy {
                        class_hash,
                        contract_address_salt,
                        calldata,
                        deploy_from_zero,
                        mut gas,
                    } => {
                        let result = handler.deploy(
                            class_hash,
                            contract_address_salt,
                            &calldata,
                            deploy_from_zero,
                            &mut gas,
                        );
                        self.sender.send(
                            Message::SyscallAnswer(SyscallAnswer::Deploy {
                                result,
                                remaining_gas: gas,
                            })
                            .wrap()?,
                        )?;
                    }
                    SyscallRequest::ReplaceClass {
                        class_hash,
                        mut gas,
                    } => {
                        let result = handler.replace_class(class_hash, &mut gas);
                        self.sender.send(
                            Message::SyscallAnswer(SyscallAnswer::ReplaceClass {
                                result,
                                remaining_gas: gas,
                            })
                            .wrap()?,
                        )?;
                    }
                    SyscallRequest::LibraryCall {
                        class_hash,
                        function_selector,
                        calldata,
                        mut gas,
                    } => {
                        let result = handler.library_call(
                            class_hash,
                            function_selector,
                            &calldata,
                            &mut gas,
                        );
                        self.sender.send(
                            Message::SyscallAnswer(SyscallAnswer::LibraryCall {
                                result,
                                remaining_gas: gas,
                            })
                            .wrap()?,
                        )?;
                    }
                    SyscallRequest::CallContract {
                        address,
                        entry_point_selector,
                        calldata,
                        mut gas,
                    } => {
                        let result = handler.call_contract(
                            address,
                            entry_point_selector,
                            &calldata,
                            &mut gas,
                        );
                        self.sender.send(
                            Message::SyscallAnswer(SyscallAnswer::CallContract {
                                result,
                                remaining_gas: gas,
                            })
                            .wrap()?,
                        )?;
                    }
                    SyscallRequest::EmitEvent {
                        keys,
                        data,
                        mut gas,
                    } => {
                        let result = handler.emit_event(&keys, &data, &mut gas);
                        self.sender.send(
                            Message::SyscallAnswer(SyscallAnswer::EmitEvent {
                                result,
                                remaining_gas: gas,
                            })
                            .wrap()?,
                        )?;
                    }
                    SyscallRequest::SendMessageToL1 {
                        to_address,
                        payload,
                        mut gas,
                    } => {
                        let result = handler.send_message_to_l1(to_address, &payload, &mut gas);
                        self.sender.send(
                            Message::SyscallAnswer(SyscallAnswer::SendMessageToL1 {
                                result,
                                remaining_gas: gas,
                            })
                            .wrap()?,
                        )?;
                    }
                    SyscallRequest::Keccak { input, mut gas } => {
                        let result = handler.keccak(&input, &mut gas);
                        self.sender.send(
                            Message::SyscallAnswer(SyscallAnswer::Keccak {
                                result,
                                remaining_gas: gas,
                            })
                            .wrap()?,
                        )?;
                    }
                },
                Message::SyscallAnswer(_) => unreachable!(),
            }
        }
    }
}

impl Drop for IsolatedExecutor {
    fn drop(&mut self) {
        let _ = self.sender.send(Message::Kill.wrap().unwrap());
        let _ = self.proc.kill();
    }
}
