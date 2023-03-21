# To run this fuzzer

## 1. Create a container to run it 

Please refer to the user guide section in this [repository](https://github.com/lambdaclass/fuzzing_examples#user-guide) to create a container with the included Dockerfile.

## 2. Run the fuzzer 

1. Clone the proyect in the container.
2. Start the enviroment following the proyect main README.
3. Run the command `HFUZZ_RUN_ARGS="-n 1" cargo hfuzz run fuzzer` within the fuzzer folder.
4. The crashes found will be stored in the hfuzz_workspace folder along with the crash report and all the inputs used.

## 3. Analice the crash 

Once you found a crash, to debug use the command `cargo hfuzz run-debug fuzzer <crash file> `