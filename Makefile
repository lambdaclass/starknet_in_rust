.PHONY: build check deps deps-macos clean compile_cairo clippy remove-venv venv-test test clean coverage


STARKNET_SOURCES=$(wildcard tests/*.cairo)
STARKNET_TARGETS=$(patsubst %.cairo,%.json,$(STARKNET_SOURCES))


%.json: %.cairo
	starknet-compile $< | python3 tests/starknet-bug-workaround.py > $@


build:
	cargo build --release

check:
	cargo check

deps:
	cargo install cargo-tarpaulin --version 0.23.1 && \
	python3 -m venv starknet-in-rs-venv
	. starknet-in-rs-venv/bin/activate && \
	pip install cairo_lang==0.10.1 && \
	deactivate

deps-macos:
	cargo install cargo-tarpaulin --version 0.23.1 && \
	python3 -m venv starknet-in-rs-venv
	. starknet-in-rs-venv/bin/activate && \
	CFLAGS=-I/opt/homebrew/opt/gmp/include LDFLAGS=-L/opt/homebrew/opt/gmp/lib pip install fastecdsa cairo_lang==0.10.1 && \
	deactivate

clean:
	-rm cairo_programs/*json
	-rm tests/*.json

compile_cairo:
	cairo-compile cairo_programs/syscalls.cairo --output cairo_programs/syscalls.json && \
	cairo-compile cairo_programs/not_main.cairo --output cairo_programs/not_main.json && \
	cairo-compile cairo_programs/contracts.cairo --output cairo_programs/contracts.json

compile-starknet: $(STARKNET_TARGETS)

clippy:
	cargo clippy --all-targets -- -D warnings

remove-venv:
	rm -rf starknet-in-rs-venv

venv-test:
	. starknet-in-rs-venv/bin/activate && $(MAKE) compile_cairo compile-starknet
	cargo test

test:
	cargo test

coverage:
	cargo tarpaulin
	rm -f default.profraw
