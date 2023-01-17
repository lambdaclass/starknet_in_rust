<div align="center">
<img src="https://starknet.io/wp-content/uploads/2021/11/favicon.png" width="150"/>
<h3>🦀 StarkNet in Rust 🦀</h3>

StarkNet library in Rust, featuring [⚡ cairo-rs ⚡](https://github.com/lambdaclass/cairo-rs) VM

<a href="https://github.com/lambdaclass/starknet_in_rust/issues/new">Report Bug</a>
·
<a href="https://github.com/lambdaclass/starknet_in_rust/issues/new">Request Feature</a>

[![codecov](https://img.shields.io/codecov/c/github/lambdaclass/starknet_in_rust)](https://codecov.io/gh/lambdaclass/starknet_in_rust)
[![license](https://img.shields.io/github/license/lambdaclass/starknet_in_rust)](/LICENSE)
![PRs Welcome][pr-welcome]
[![Telegram Chat][tg-badge]][tg-url]

[pr-welcome]: https://img.shields.io/static/v1?color=orange&label=PRs&style=flat&message=welcome
[tg-badge]: https://img.shields.io/static/v1?color=green&logo=telegram&label=chat&style=flat&message=join
[tg-url]: https://t.me/starknet_rs

</div>

## Table of Contents
- [Disclaimer](#disclaimer)
- [About](#about)
- [Requisites](#requisites)
- [Setup](#setup)
- [Test](#test)
- [Related Projects](#related-projects)
- [Documentation](#documentation)
  * [StarkNet](#starknet)
- [License](#license)


## Disclaimer

⚠️ This project is a work-in-progress and is not ready for production yet. Use at your own risk. ⚠️

## About

`starknet_in_rust` is an implentation of [StarkNet](https://github.com/starkware-libs/cairo-lang/tree/master/src/starkware/starknet) in Rust.
It makes use of [cairo-rs](https://github.com/lambdaclass/cairo-rs), the Rust implementation of the Cairo virtual machine.

## Requisites
- Rust 1.62
- A working installation of cairo-lang 0.10.2 (for compiling the cairo files)

## Setup

Run the following make targets to have a working environment:
```bash
$ make deps
$ source starknet-in-rs-venv/bin/activate
$ make compile_cairo
$ deactivate
$ make build
```

Check the [Makefile](/Makefile) for additional targets.

## Test
Run the following command:
```bash
$ make test
```

## Related Projects

- [cairo-rs](https://github.com/lambdaclass/cairo-rs): A fast implementation of the Cairo VM in Rust.
- [cairo-rs-py](https://github.com/lambdaclass/cairo-rs-py): Bindings for using cairo-rs from Python code.

## Documentation

### StarkNet
- [StarkNet's Architecture Review](https://david-barreto.com/starknets-architecture-review/)
- [StarkNet State](https://docs.starknet.io/documentation/architecture_and_concepts/State/starknet-state/)
- [Array Hashing](https://docs.starknet.io/documentation/architecture_and_concepts/Hashing/hash-functions/#array_hashing)

## License

[MIT](/LICENSE)
