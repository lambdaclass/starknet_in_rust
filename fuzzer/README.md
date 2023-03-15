# To run this fuzzer

## 1. Create a container to run it 

use user guide section on this [repository](https://github.com/lambdaclass/fuzzing_examples) to create a container with the dockerfile in it

## 2. Run the fuzzer 

1. clone the proyect in the container
2. start the enviroment following the proyect main README
3. run the command `HFUZZ_RUN_ARGS="-n 1" cargo hfuzz run fuzzer` within the fuzzer folder
4. the crashes found will be stored in the hfuzz_workspace folder along with the crash report and all the inputs used

As this fuzzer compiles several files while running it causes a crash, its already documented so unless the fuzzer marks the crash fund is unique: 1 , the error triggered doesn´t reproduce a real error.

## 3. Analice the crash 

Once you found a crash, to debug use the command `cargo hfuzz run-debug fuzzer <crash file> `