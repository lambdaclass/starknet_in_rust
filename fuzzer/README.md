# To run this fuzzer

## 1. Create a container to run it 

Please refer to the user guide section in this [repository](https://github.com/lambdaclass/fuzzing_examples#user-guide) to create a container with the included Dockerfile.

## 2. Run the fuzzer 

1. Start the container as explained in last section.
2. Clone the proyect in the container with `git clone -b main --single-branch --depth 1 https://github.com/lambdaclass/starknet_in_rust.git`.
3. Run `make deps` and `source starknet-venv/bin/activate` to have a working environment.
4. Run the command `HFUZZ_RUN_ARGS="-n 1" cargo hfuzz run fuzzer` within the _fuzzer_ folder.

The crashes found will be stored in the _hfuzz_workspace_ folder along with the reports and all the inputs used.

## 3. Analyze the crash 

Once you find a crash, use the command `cargo hfuzz run-debug fuzzer <crash file> ` to debug.
