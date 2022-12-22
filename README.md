# Starknet in Rust

`starknet_in_rust` is a implentation of [Starknet](https://github.com/starkware-libs/cairo-lang/tree/master/src/starkware/starknet) in Rust.
It makes use of [cairo-rs](https://github.com/lambdaclass/cairo-rs), the Rust implementation of the Cairo virtual machine.

## Requisites
- Rust 1.62
- A working installation of cairo-lang (for compiling the cairo files)

## Setup

Run the following make targets to have a working environment:
```bash
$ make deps
$ make compile_cairo
$ make build
```

Check the [Makefile](/Makefile) for additional targets.

## Related projects

- [cairo-rs](https://github.com/lambdaclass/cairo-rs): A fast implementation of the Cairo VM in Rust.
- [cairo-rs-py](https://github.com/lambdaclass/cairo-rs-py): Bindings for using cairo-rs from Python code.


## License

[MIT](/LICENSE)
