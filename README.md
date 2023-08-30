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
  - [Installation](#installation)
    - [How to manually install the script dependencies](#how-to-manually-install-the-script-dependencies)
- [🚀 Usage](#-usage)
  - [Running simple contracts](#running-simple-contracts)
  - [Using the Cli](#using-the-cli)
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
- Rust 1.70
- A working installation of cairo-lang 0.12 (for compiling the cairo files)
- [Optional, for testing purposes] Heaptrack 

### Installation

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

#### RPC State Reader

In order to use the RPC state reader add an Infura API key in a `.env` file at root:

```
INFURA_API_KEY={some_key}
```

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



## 🚀 Usage

### Running simple contracts

You can find a tutorial on running contracts [here](/examples/contract_execution/README.md).

### Using the CLI
You can find an example on how to use the CLI [here](/docs/CLI_USAGE_EXAMPLE.md)

### Testing

[Add an Infura API key.](#rpc-state-reader)

Run the following command:
```bash
$ make test
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
