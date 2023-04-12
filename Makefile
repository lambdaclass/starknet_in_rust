.PHONY: build check clean clippy compile-cairo compile-starknet coverage deps test heaptrack check-python-version compile-abi


OS := $(shell uname)
ifeq ($(OS), Darwin)
	CFLAGS  += -I/opt/homebrew/opt/gmp/include
	LDFLAGS += -L/opt/homebrew/opt/gmp/lib
endif


CAIRO_SOURCES=$(wildcard cairo_programs/*.cairo)
CAIRO_TARGETS=$(patsubst %.cairo,%.json,$(CAIRO_SOURCES))
CAIRO_ABI_TARGETS=$(patsubst %.cairo,%_abi.json,$(CAIRO_SOURCES))

STARKNET_SOURCES=$(wildcard starknet_programs/*.cairo)
STARKNET_TARGETS=$(patsubst %.cairo,%.json,$(STARKNET_SOURCES))
STARKNET_ABI_TARGETS=$(patsubst %.cairo,%_abi.json,$(STARKNET_SOURCES))

BUILTIN_SOURCES=$(wildcard starknet_programs/*.cairo)
BUILTIN_TARGETS=$(patsubst %.cairo,%.json,$(BUILTIN_SOURCES))


#
# VENV rules.
#

deps-venv:
	pip install \
		fastecdsa \
		typeguard==2.13.0 \
		openzeppelin-cairo-contracts==0.6.1 \
		maturin \
		cairo-lang==0.10.3

compile-cairo: $(CAIRO_TARGETS) $(CAIRO_ABI_TARGETS)
compile-starknet: $(STARKNET_TARGETS) $(STARKNET_ABI_TARGETS)

cairo_programs/%.json cairo_programs/%_abi.json: cairo_programs/%.cairo
	. starknet-venv/bin/activate && cd cairo_programs/ && cairo-compile $(shell grep "^// @compile-flags += .*$$" $< | cut -c 22-) ../$< --output ../$@ || rm ../$@

starknet_programs/%.json starknet_programs/%_abi.json: starknet_programs/%.cairo
	. starknet-venv/bin/activate && \
	cd starknet_programs/ && \
	starknet-compile $(shell grep "^// @compile-flags += .*$$" $< | cut -c 22-) \
	../$< \
	--output ./$*.json \
	--abi ./$*_abi.json \
	|| rm ./$*.json ./$*_abi.json
# Compiles .cairo files into .json files. if the command fails, then it removes all of the .json files

#
# Normal rules.
#

build: compile-cairo compile-starknet
	cargo build --release --all

check: compile-cairo compile-starknet
	cargo check --all

deps: check-python-version 
	cargo install flamegraph --version 0.6.2
	cargo install cargo-llvm-cov --version 0.5.14
	rustup toolchain install nightly
	python3 -m venv starknet-venv
	. starknet-venv/bin/activate && $(MAKE) deps-venv

clean:
	-rm -rf starknet-venv/
	-rm -f cairo_programs/*.json
	-rm -f starknet_programs/*.json
	-rm -f tests/*.json

clippy: compile-cairo compile-starknet
	cargo clippy --all --all-targets -- -D warnings

test: compile-cairo compile-starknet
	cargo test --all --exclude starknet-rs-py

test-py: compile-cairo compile-starknet
	. starknet-venv/bin/activate && cargo test -p starknet-rs-py --no-default-features --features embedded-python

coverage: compile-cairo compile-starknet compile-abi
	cargo +nightly llvm-cov --ignore-filename-regex 'main.rs'
	cargo +nightly llvm-cov report --lcov --ignore-filename-regex 'main.rs' --output-path lcov.info

heaptrack:
	./scripts/heaptrack.sh

flamegraph: compile-cairo compile-starknet
	CARGO_PROFILE_RELEASE_DEBUG=true cargo flamegraph --root --bench internals
