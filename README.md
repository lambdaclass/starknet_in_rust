<div align="center">
<img src="./starknet_logo.svg" width="150"/>

### 🦀 Starknet in Rust 🦀

Starknet transaction execution library in Rust, featuring [⚡cairo-vm⚡](https://github.com/lambdaclass/cairo-vm)

[Report Bug](https://github.com/lambdaclass/starknet_in_rust/issues/new?labels=bug&title=bug%3A+) · [Request Feature](https://github.com/lambdaclass/starknet_in_rust/issues/new?labels=enhancement&title=feat%3A+)

[![codecov](https://img.shields.io/codecov/c/github/lambdaclass/starknet_in_rust)](https://codecov.io/gh/lambdaclass/starknet_in_rust)
[![license](https://img.shields.io/github/license/lambdaclass/starknet_in_rust)](/LICENSE)
[![pr-welcome]](#-contributing)
[![Telegram Chat][tg-badge]][tg-url]

[pr-welcome]: https://img.shields.io/static/v1?color=orange&label=PRs&style=flat&message=welcome
[tg-badge]: https://img.shields.io/endpoint?url=https%3A%2F%2Ftg.sumanjay.workers.dev%2FLambdaStarkNet%2F&logo=telegram&label=chat&color=neon
[tg-url]: https://t.me/LambdaStarkNet

</div>

## Table of Contents
- [Table of Contents](#table-of-contents)
- [⚠️ Disclaimer](#️-disclaimer)
- [📖 About](#-about)
- [🌅 Getting Started](#-getting-started)
  - [Dependencies](#dependencies)
  - [Requirements](#requirements)
  - [Installation](#installation)
    - [How to manually install the script dependencies](#how-to-manually-install-the-script-dependencies)
- [🚀 Usage](#-usage)
  - [Running simple contracts](#running-simple-contracts)
  - [Testing](#testing)
  - [Profiling](#profiling)
  - [Benchmarking](#benchmarking)
- [🛠 Contributing](#-contributing)
- [🌞 Related Projects](#-related-projects)
- [📚 Documentation](#-documentation)
  - [Starknet](#starknet)
- [⚖️ License](#️-license)

## ⚠️ Disclaimer

🚧 This project is a work-in-progress and is not ready for production yet. Use at your own risk. 🚧

## 📖 About

`starknet_in_rust` is an implementation of [Starknet](https://github.com/starkware-libs/cairo-lang/tree/master/src/starkware/starknet) in Rust.
It makes use of [cairo-vm](https://github.com/lambdaclass/cairo-vm), the Rust implementation of the Cairo virtual machine.

## 🌅 Getting Started

### Dependencies
- Rust 1.74.1
- A working installation of cairo-lang 0.12 (for compiling the cairo files)
- [Optional, for testing purposes] Heaptrack

### Requirements

You need to have a version of `Python 3` installed. If you don't have it, you can install it for Debian-based GNU/Linux distributions with:
```shell
sudo apt install python3.9
```
On MacOS you can use Homebrew:
```shell
brew install python@3.9
```
Optionally, for setting environment, you can install `pyenv` for MacOS:
```shell
brew install pyenv
```

### Installation

If you run `make` on it's own it will print out the main targets and their description.

Run the following make targets to have a working environment (if in Mac or if you encounter an error, see the subsection below):

#### Linux (x86-64)
```bash
$ make deps
$ make build
```

#### OSX (Apple Silicon)
```bash
$ make deps-macos
$ make build
```

Check the [Makefile](/Makefile) for additional targets.

#### How to manually install the script dependencies

`cairo-lang` requires the `gmp` library to build.
You can install it on Debian-based GNU/Linux distributions with:
```shell
sudo apt install -y libgmp3-dev
```

In Mac you can use Homebrew:
```shell
brew install gmp
```

In Mac you'll also need to tell the script where to find the gmp lib:
```shell
export CFLAGS=-I/opt/homebrew/opt/gmp/include LDFLAGS=-L/opt/homebrew/opt/gmp/lib
```

### Cairo Native support

Starknet in Rust can be integrated with [Cairo Native](https://github.com/lambdaclass/cairo_native), which makes the execution of sierra programs possible through native machine code. To use it, the following needs to be setup:

- LLVM `17` needs to be installed and the `MLIR_SYS_170_PREFIX` and `TABLEGEN_170_PREFIX` environment variable needs to point to said installation. In macOS, run
  ```
  brew install llvm@17
  export MLIR_SYS_170_PREFIX=/opt/homebrew/opt/llvm@17
  export LLVM_SYS_170_PREFIX=/opt/homebrew/opt/llvm@17
  export TABLEGEN_170_PREFIX=/opt/homebrew/opt/llvm@17
  ```
  and you're set.

Afterwards, compiling with the feature flag `cairo-native` will enable native execution. You can check out some example test code that uses it under `tests/cairo_native.rs`.

#### Using ahead of time compilation with Native.

Currently cairo-native with AOT needs a runtime library in a known place. For this you need to compile the [cairo-native-runtime](https://github.com/lambdaclass/cairo_native/tree/main/runtime) crate and point the following environment variable to a folder containing the dynamic library. The path **must** be an absolute path.

```bash
CAIRO_NATIVE_RUNTIME_LIBDIR=/absolute/path/to/cairo-native/target/release
```

If you don't do this you will get a linker error when using AOT.

## 🚀 Usage

### Running simple contracts

You can find a tutorial on running contracts [here](/examples/contract_execution/README.md).

### Customization

#### Contract class cache behavior

`starknet_in_rust` supports caching contracts in memory. Caching the contracts is useful for
avoiding excessive RPC API usage and keeping the contract class deserialization overhead to the
minimum. The project provides two builtin cache policies: null and permanent. The null cache behaves
as if there was no cache at all. The permanent cache caches everything in memory forever.

In addition to those two, an example is provided that implements and uses an LRU cache policy.
Long-running applications should ideally implement a cache algorithm suited to their needs or
alternatively use our example's implementation to avoid spamming the API when using the null cache
or blowing the memory usage when running with the permanent cache.

Customized cache policies may be used by implementing the `ContractClassCache` trait. Check out our
[LRU cache example](examples/lru_cache/main.rs) for more details. Updating the cache requires
manually merging the local state cache into the shared cache manually. This can be done by calling
the `drain_private_contract_class_cache` on the `CachedState` instance.

```rs
// To use the null cache (aka. no cache at all), create the state as follows:
let cache = Arc::new(NullContractClassCache::default());
let state1 = CachedState::new(state_reader.clone(), cache.clone());
let state2 = CachedState::new(state_reader.clone(), cache.clone()); // Cache is reused.

// Insert state usage here.

// The null cache doesn't have any method to extend it since it has no data.
```

```rs
// If the permanent cache is preferred, then use `PermanentContractClassCache` instead:
let cache = Arc::new(PermanentContractClassCache::default());
let state1 = CachedState::new(state_reader.clone(), cache.clone());
let state2 = CachedState::new(state_reader.clone(), cache.clone()); // Cache is reused.

// Insert state usage here.

// Extend the shared cache with the states' contracts after using them.
cache.extend(state1.state.drain_private_contract_class_cache());
cache.extend(state2.state.drain_private_contract_class_cache());
```

#### Logging configuration

This project uses the [`tracing`](https://crates.io/crates/tracing) crate as a library. Check out
its documentation for more information.

### Testing

#### Logging configuration

This project uses the [`tracing`](https://crates.io/crates/tracing) crate as a library. Check out
its documentation for more information.

### Testing

Run the following command:
```bash
$ make test
```
Take into account that some tests use the [RPC State Reader](#rpc-state-reader) so you need a full-node instance or an RPC provider that supports Starknet API version 0.6.0.

### RPC State Reader

[The RPC State Reader](/rpc_state_reader/) provides a way of reading the real Starknet State when using Starknet in Rust.
So you can re-execute an existing transaction in any of the Starknet networks in an easy way, just providing the transaction hash, the block number and the network in which the transaction was executed.
Every time it needs to read a storage value, a contract class or contract, it goes to an RPC to fetch them.

Right now we are using it for internal testing but we plan to release it as a library soon.

#### How to configure it
In order to use the RPC state reader add the endpoints to a full node instance or RPC provider supporting Starknet API version 0.5.0 in a `.env` file at root:

```
RPC_ENDPOINT_TESTNET={some endpoint}
RPC_ENDPOINT_MAINNET={some endpoint}
```

### Profiling

Run the following command:

```bash
$ make flamegraph
```

to generate a flamegraph with info of the execution of the main operations.

### Benchmarking

Read the 'bench_integration.py' file to identify which lines need to be commented out for accurate results. Comment out those lines and then run the following command:

```bash
$ make benchmark
```

## 🛠 Contributing

The open source community is a fantastic place for learning, inspiration, and creation, and this is all thanks to contributions from people like you. Your contributions are **greatly appreciated**.

If you have any suggestions for how to improve the project, please feel free to fork the repo and create a pull request, or [open an issue](https://github.com/lambdaclass/starknet_in_rust/issues/new?labels=enhancement&title=feat%3A+) with the tag 'enhancement'.

1. Fork the Project
2. Create your Feature Branch (`git checkout -b feature/AmazingFeature`)
3. Commit your Changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the Branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

And don't forget to give the project a star! ⭐ Thank you again for your support.

## 🌞 Related Projects

- [cairo-vm](https://github.com/lambdaclass/cairo-vm): A fast implementation of the Cairo VM in Rust.
- [cairo-vm-py](https://github.com/lambdaclass/cairo-vm-py): Bindings for using cairo-vm from Python code.

## 📚 Documentation

### Starknet
- [Starknet's Architecture Review](https://david-barreto.com/starknets-architecture-review/)
- [Starknet State](https://docs.starknet.io/documentation/architecture_and_concepts/State/starknet-state/)
- [Array Hashing](https://docs.starknet.io/documentation/architecture_and_concepts/Hashing/hash-functions/#array_hashing)

## ⚖️ License

This project is licensed under the Apache 2.0 license.

See [LICENSE](/LICENSE) for more information.
