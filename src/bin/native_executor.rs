use std::{cell::RefCell, path::PathBuf, rc::Rc};

use cairo_lang_utils::ResultHelper;
use cairo_native::{
    context::NativeContext,
    executor::JitNativeExecutor,
    metadata::syscall_handler::SyscallHandlerMeta,
    starknet::{StarkNetSyscallHandler, SyscallResult},
    utils::find_entry_point_by_idx,
};
use cairo_vm::Felt252 as Felt;
use ipc_channel::ipc::{IpcOneShotServer, IpcReceiver, IpcSender};
use starknet_in_rust::sandboxing::{Message, SyscallAnswer, SyscallRequest, WrappedMessage};
use tracing::instrument;

#[derive(Debug)]
struct SyscallHandler {
    sender: IpcSender<WrappedMessage>,
    receiver: Rc<RefCell<IpcReceiver<WrappedMessage>>>,
}

impl StarkNetSyscallHandler for SyscallHandler {
    #[instrument(skip(self))]
    fn get_block_hash(&mut self, block_number: u64, gas: &mut u128) -> SyscallResult<Felt> {
        self.sender
            .send(
                Message::SyscallRequest(SyscallRequest::GetBlockHash {
                    block_number,
                    gas: *gas,
                })
                .wrap()
                .unwrap(),
            )
            .expect("failed to send");
        let result = self
            .receiver
            .borrow()
            .recv()
            .on_err(|e| tracing::error!("error receiving: {:?}", e))
            .unwrap()
            .to_msg()
            .unwrap();

        if let Message::SyscallAnswer(SyscallAnswer::GetBlockHash {
            result,
            remaining_gas,
        }) = result
        {
            *gas = remaining_gas;
            result
        } else {
            tracing::error!("wrong message received: {:#?}", result);
            panic!();
        }
    }

    #[instrument(skip(self))]
    fn get_execution_info(
        &mut self,
        gas: &mut u128,
    ) -> SyscallResult<cairo_native::starknet::ExecutionInfo> {
        self.sender
            .send(
                Message::SyscallRequest(SyscallRequest::GetExecutionInfo { gas: *gas })
                    .wrap()
                    .unwrap(),
            )
            .expect("failed to send");
        let result = self
            .receiver
            .borrow()
            .recv()
            .on_err(|e| tracing::error!("error receiving: {:?}", e))
            .unwrap()
            .to_msg()
            .unwrap();

        if let Message::SyscallAnswer(SyscallAnswer::GetExecutionInfo {
            result,
            remaining_gas,
        }) = result
        {
            *gas = remaining_gas;
            result
        } else {
            tracing::error!("wrong message received: {:#?}", result);
            panic!();
        }
    }

    fn deploy(
        &mut self,
        class_hash: Felt,
        contract_address_salt: Felt,
        calldata: &[Felt],
        deploy_from_zero: bool,
        gas: &mut u128,
    ) -> SyscallResult<(Felt, Vec<Felt>)> {
        self.sender
            .send(
                Message::SyscallRequest(SyscallRequest::Deploy {
                    class_hash,
                    contract_address_salt,
                    calldata: calldata.to_vec(),
                    deploy_from_zero,
                    gas: *gas,
                })
                .wrap()
                .unwrap(),
            )
            .expect("failed to send");
        let result = self
            .receiver
            .borrow()
            .recv()
            .on_err(|e| tracing::error!("error receiving: {:?}", e))
            .unwrap()
            .to_msg()
            .unwrap();

        if let Message::SyscallAnswer(SyscallAnswer::Deploy {
            result,
            remaining_gas,
        }) = result
        {
            *gas = remaining_gas;
            result
        } else {
            tracing::error!("wrong message received: {:#?}", result);
            panic!();
        }
    }

    fn replace_class(&mut self, class_hash: Felt, gas: &mut u128) -> SyscallResult<()> {
        self.sender
            .send(
                Message::SyscallRequest(SyscallRequest::ReplaceClass {
                    class_hash,
                    gas: *gas,
                })
                .wrap()
                .unwrap(),
            )
            .expect("failed to send");
        let result = self
            .receiver
            .borrow()
            .recv()
            .on_err(|e| tracing::error!("error receiving: {:?}", e))
            .unwrap()
            .to_msg()
            .unwrap();

        if let Message::SyscallAnswer(SyscallAnswer::ReplaceClass {
            result,
            remaining_gas,
        }) = result
        {
            *gas = remaining_gas;
            result
        } else {
            tracing::error!("wrong message received: {:#?}", result);
            panic!();
        }
    }

    fn library_call(
        &mut self,
        class_hash: Felt,
        function_selector: Felt,
        calldata: &[Felt],
        gas: &mut u128,
    ) -> SyscallResult<Vec<Felt>> {
        self.sender
            .send(
                Message::SyscallRequest(SyscallRequest::LibraryCall {
                    class_hash,
                    function_selector,
                    calldata: calldata.to_vec(),
                    gas: *gas,
                })
                .wrap()
                .unwrap(),
            )
            .expect("failed to send");
        let result = self
            .receiver
            .borrow()
            .recv()
            .on_err(|e| tracing::error!("error receiving: {:?}", e))
            .unwrap()
            .to_msg()
            .unwrap();

        if let Message::SyscallAnswer(SyscallAnswer::LibraryCall {
            result,
            remaining_gas,
        }) = result
        {
            *gas = remaining_gas;
            result
        } else {
            tracing::error!("wrong message received: {:#?}", result);
            panic!();
        }
    }

    fn call_contract(
        &mut self,
        address: Felt,
        entry_point_selector: Felt,
        calldata: &[Felt],
        gas: &mut u128,
    ) -> SyscallResult<Vec<Felt>> {
        self.sender
            .send(
                Message::SyscallRequest(SyscallRequest::CallContract {
                    address,
                    entry_point_selector,
                    calldata: calldata.to_vec(),
                    gas: *gas,
                })
                .wrap()
                .unwrap(),
            )
            .expect("failed to send");
        let result = self
            .receiver
            .borrow()
            .recv()
            .on_err(|e| tracing::error!("error receiving: {:?}", e))
            .unwrap()
            .to_msg()
            .unwrap();

        if let Message::SyscallAnswer(SyscallAnswer::CallContract {
            result,
            remaining_gas,
        }) = result
        {
            *gas = remaining_gas;
            result
        } else {
            tracing::error!("wrong message received: {:#?}", result);
            panic!();
        }
    }

    fn storage_read(
        &mut self,
        address_domain: u32,
        address: Felt,
        gas: &mut u128,
    ) -> SyscallResult<Felt> {
        self.sender
            .send(
                Message::SyscallRequest(SyscallRequest::StorageRead {
                    address_domain,
                    address,
                    gas: *gas,
                })
                .wrap()
                .unwrap(),
            )
            .expect("failed to send");
        let result = self
            .receiver
            .borrow()
            .recv()
            .on_err(|e| tracing::error!("error receiving: {:?}", e))
            .unwrap()
            .to_msg()
            .unwrap();

        if let Message::SyscallAnswer(SyscallAnswer::StorageRead {
            result,
            remaining_gas,
        }) = result
        {
            *gas = remaining_gas;
            result
        } else {
            tracing::error!("wrong message received: {:#?}", result);
            panic!();
        }
    }

    fn storage_write(
        &mut self,
        address_domain: u32,
        address: Felt,
        value: Felt,
        gas: &mut u128,
    ) -> SyscallResult<()> {
        self.sender
            .send(
                Message::SyscallRequest(SyscallRequest::StorageWrite {
                    address_domain,
                    address,
                    value,
                    gas: *gas,
                })
                .wrap()
                .unwrap(),
            )
            .expect("failed to send");
        let result = self
            .receiver
            .borrow()
            .recv()
            .on_err(|e| tracing::error!("error receiving: {:?}", e))
            .unwrap()
            .to_msg()
            .unwrap();

        if let Message::SyscallAnswer(SyscallAnswer::StorageWrite {
            result,
            remaining_gas,
        }) = result
        {
            *gas = remaining_gas;
            result
        } else {
            tracing::error!("wrong message received: {:#?}", result);
            panic!();
        }
    }

    fn emit_event(&mut self, keys: &[Felt], data: &[Felt], gas: &mut u128) -> SyscallResult<()> {
        self.sender
            .send(
                Message::SyscallRequest(SyscallRequest::EmitEvent {
                    keys: keys.to_vec(),
                    data: data.to_vec(),
                    gas: *gas,
                })
                .wrap()
                .unwrap(),
            )
            .expect("failed to send");
        let result = self
            .receiver
            .borrow()
            .recv()
            .on_err(|e| tracing::error!("error receiving: {:?}", e))
            .unwrap()
            .to_msg()
            .unwrap();

        if let Message::SyscallAnswer(SyscallAnswer::EmitEvent {
            result,
            remaining_gas,
        }) = result
        {
            *gas = remaining_gas;
            result
        } else {
            tracing::error!("wrong message received: {:#?}", result);
            panic!();
        }
    }

    fn send_message_to_l1(
        &mut self,
        to_address: Felt,
        payload: &[Felt],
        gas: &mut u128,
    ) -> SyscallResult<()> {
        self.sender
            .send(
                Message::SyscallRequest(SyscallRequest::SendMessageToL1 {
                    to_address,
                    payload: payload.to_vec(),
                    gas: *gas,
                })
                .wrap()
                .unwrap(),
            )
            .expect("failed to send");
        let result = self
            .receiver
            .borrow()
            .recv()
            .on_err(|e| tracing::error!("error receiving: {:?}", e))
            .unwrap()
            .to_msg()
            .unwrap();

        if let Message::SyscallAnswer(SyscallAnswer::SendMessageToL1 {
            result,
            remaining_gas,
        }) = result
        {
            *gas = remaining_gas;
            result
        } else {
            tracing::error!("wrong message received: {:#?}", result);
            panic!();
        }
    }

    fn keccak(
        &mut self,
        input: &[u64],
        gas: &mut u128,
    ) -> SyscallResult<cairo_native::starknet::U256> {
        self.sender
            .send(
                Message::SyscallRequest(SyscallRequest::Keccak {
                    input: input.to_vec(),
                    gas: *gas,
                })
                .wrap()
                .unwrap(),
            )
            .expect("failed to send");
        let result = self
            .receiver
            .borrow()
            .recv()
            .on_err(|e| tracing::error!("error receiving: {:?}", e))
            .unwrap()
            .to_msg()
            .unwrap();

        if let Message::SyscallAnswer(SyscallAnswer::Keccak {
            result,
            remaining_gas,
        }) = result
        {
            *gas = remaining_gas;
            result
        } else {
            tracing::error!("wrong message received: {:#?}", result);
            panic!();
        }
    }

    fn secp256k1_add(
        &mut self,
        _p0: cairo_native::starknet::Secp256k1Point,
        _p1: cairo_native::starknet::Secp256k1Point,
        _gas: &mut u128,
    ) -> SyscallResult<Option<cairo_native::starknet::Secp256k1Point>> {
        todo!()
    }

    fn secp256k1_get_point_from_x(
        &self,
        _x: cairo_native::starknet::U256,
        _y_parity: bool,
        _gas: &mut u128,
    ) -> SyscallResult<Option<cairo_native::starknet::Secp256k1Point>> {
        todo!()
    }

    fn secp256k1_get_xy(
        &self,
        _p: cairo_native::starknet::Secp256k1Point,
        _gas: &mut u128,
    ) -> SyscallResult<(cairo_native::starknet::U256, cairo_native::starknet::U256)> {
        todo!()
    }

    fn secp256k1_mul(
        &self,
        _p: cairo_native::starknet::Secp256k1Point,
        _m: cairo_native::starknet::U256,
        _gas: &mut u128,
    ) -> SyscallResult<Option<cairo_native::starknet::Secp256k1Point>> {
        todo!()
    }

    fn secp256k1_new(
        &self,
        _x: cairo_native::starknet::U256,
        _y: cairo_native::starknet::U256,
        _gas: &mut u128,
    ) -> SyscallResult<Option<cairo_native::starknet::Secp256k1Point>> {
        todo!()
    }

    fn secp256r1_add(
        &self,
        _p0: cairo_native::starknet::Secp256k1Point,
        _p1: cairo_native::starknet::Secp256k1Point,
        _gas: &mut u128,
    ) -> SyscallResult<Option<cairo_native::starknet::Secp256k1Point>> {
        todo!()
    }

    fn secp256r1_get_point_from_x(
        &self,
        _x: cairo_native::starknet::U256,
        _y_parity: bool,
        _gas: &mut u128,
    ) -> SyscallResult<Option<cairo_native::starknet::Secp256k1Point>> {
        todo!()
    }

    fn secp256r1_get_xy(
        &self,
        _p: cairo_native::starknet::Secp256k1Point,
        _gas: &mut u128,
    ) -> SyscallResult<(cairo_native::starknet::U256, cairo_native::starknet::U256)> {
        todo!()
    }

    fn secp256r1_mul(
        &self,
        _p: cairo_native::starknet::Secp256k1Point,
        _m: cairo_native::starknet::U256,
        _gas: &mut u128,
    ) -> SyscallResult<Option<cairo_native::starknet::Secp256k1Point>> {
        todo!()
    }

    fn secp256r1_new(
        &mut self,
        _x: cairo_native::starknet::U256,
        _y: cairo_native::starknet::U256,
        _gas: &mut u128,
    ) -> SyscallResult<Option<cairo_native::starknet::Secp256k1Point>> {
        todo!()
    }

    fn pop_log(&mut self) {
        todo!()
    }

    fn set_account_contract_address(&mut self, _contract_address: Felt) {
        todo!()
    }

    fn set_block_number(&mut self, _block_number: u64) {
        todo!()
    }

    fn set_block_timestamp(&mut self, _block_timestamp: u64) {
        todo!()
    }

    fn set_caller_address(&mut self, _address: Felt) {
        todo!()
    }

    fn set_chain_id(&mut self, _chain_id: Felt) {
        todo!()
    }

    fn set_contract_address(&mut self, _address: Felt) {
        todo!()
    }

    fn set_max_fee(&mut self, _max_fee: u128) {
        todo!()
    }

    fn set_nonce(&mut self, _nonce: Felt) {
        todo!()
    }

    fn set_sequencer_address(&mut self, _address: Felt) {
        todo!()
    }

    fn set_signature(&mut self, _signature: &[Felt]) {
        todo!()
    }

    fn set_transaction_hash(&mut self, _transaction_hash: Felt) {
        todo!()
    }

    fn set_version(&mut self, _version: Felt) {
        todo!()
    }

    fn get_execution_info_v2(
        &mut self,
        _remaining_gas: &mut u128,
    ) -> SyscallResult<cairo_native::starknet::ExecutionInfoV2> {
        todo!()
    }
}

pub fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = std::env::args();

    let pid = std::process::id();

    let log_dir = PathBuf::from(
        std::env::var("CAIRO_EXECUTOR_LOGDIR").unwrap_or("executor_logs/".to_string()),
    );
    let file_appender =
        tracing_appender::rolling::daily(log_dir, format!("cairo-executor.{pid}.log"));

    tracing_subscriber::fmt()
        .with_writer(file_appender)
        .with_ansi(false)
        .init();

    if args.len() < 2 {
        tracing::error!("missing server ipc name");
        std::process::exit(1);
    }

    let server = args.nth(1).unwrap();
    let (sv, name) = IpcOneShotServer::<WrappedMessage>::new()?;
    println!("{name}"); // print to let know
    let sender = IpcSender::connect(server.clone())?;
    sender.send(Message::Ping.wrap()?)?;
    tracing::info!("connected to {server:?}");
    let (receiver, msg) = sv.accept()?;
    let receiver = Rc::new(RefCell::new(receiver));
    tracing::info!("accepted {receiver:?}");
    assert_eq!(msg, Message::Ping.wrap()?);

    let native_context = NativeContext::new();
    tracing::info!("initialized native context");

    let mut syscall_handler = SyscallHandler {
        sender: sender.clone(),
        receiver: receiver.clone(),
    };

    loop {
        tracing::info!("waiting for message");

        let message: Message = receiver.borrow().recv()?.to_msg()?;

        match message {
            Message::ExecuteJIT {
                id,
                program,
                inputs,
                function_idx,
                gas,
            } => {
                tracing::info!("Message: ExecuteJIT");
                sender.send(Message::Ack(id).wrap()?)?;
                tracing::info!("sent ack: {:?}", id);
                let program = program.into_v1()?.program;
                let native_program = native_context.compile(&program)?;

                let entry_point_fn = find_entry_point_by_idx(&program, function_idx).unwrap();

                let fn_id = &entry_point_fn.id;

                let native_executor =
                    JitNativeExecutor::from_native_module(native_program, Default::default());

                let result = native_executor.invoke_contract_dynamic(
                    fn_id,
                    &inputs,
                    gas,
                    Some(&SyscallHandlerMeta::new(&mut syscall_handler)),
                )?;

                tracing::info!("invoked with result: {:?}", result);

                sender.send(Message::ExecutionResult { id, result }.wrap()?)?;

                tracing::info!("sent result msg");
            }
            Message::ExecutionResult { .. } => {}
            Message::Ack(_) => {}
            Message::Ping => {
                tracing::info!("Message: Ping");
                sender.send(Message::Ping.wrap()?)?;
            }
            Message::Kill => {
                tracing::info!("Message: KILL");
                break;
            }
            Message::SyscallRequest(_) => todo!(),
            Message::SyscallAnswer(_) => todo!(),
        }
    }

    Ok(())
}
