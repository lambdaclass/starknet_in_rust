#[contract]
mod GetExecutionInfo {

    use starknet::info::get_execution_info;

    #[external]
    fn get_info() {
        let info = get_execution_info();
    }
}
