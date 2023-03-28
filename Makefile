.PHONY: build check clean clippy compile-cairo compile-starknet coverage deps deps-macos remove-venv test heaptrack check-python-version compile-abi


OS := $(shell uname)
ifeq ($(OS), Darwin)
	CFLAGS  += -I/opt/homebrew/opt/gmp/include
	LDFLAGS += -L/opt/homebrew/opt/gmp/lib
endif


CAIRO_SOURCES=$(wildcard cairo_programs/*.cairo)
CAIRO_TARGETS=$(patsubst %.cairo,%.json,$(CAIRO_SOURCES))

STARKNET_SOURCES=$(wildcard starknet_programs/*.cairo)
STARKNET_TARGETS=$(patsubst %.cairo,%.json,$(STARKNET_SOURCES))

BUILTIN_SOURCES=$(wildcard starknet_programs/*.cairo)
BUILTIN_TARGETS=$(patsubst %.cairo,%.json,$(BUILTIN_SOURCES))


#
# VENV rules.
#

deps-venv:
	pip install \
		fastecdsa \
		typeguard==2.13.0 \
		maturin \
		cairo-lang==0.10.3

compile-cairo: $(CAIRO_TARGETS)
compile-starknet: $(STARKNET_TARGETS)

cairo_programs/%.json: cairo_programs/%.cairo
	. starknet-venv/bin/activate && cd cairo_programs/ && cairo-compile $(shell grep "^// @compile-flags += .*$$" $< | cut -c 22-) ../$< --output ../$@ || rm ../$@

starknet_programs/%.json: starknet_programs/%.cairo
	. starknet-venv/bin/activate && cd starknet_programs/ && starknet-compile $(shell grep "^// @compile-flags += .*$$" $< | cut -c 22-) ../$< --output ../$@ || rm ../$@
# Compiles .cairo files into .json files. if the command fails, then it removes all of the .json files

#
# Normal rules.
#

compile-abi:
	. starknet-venv/bin/activate
	starknet-compile starknet_programs/fibonacci.cairo \
		--output starknet_programs/fibonacci_compiled.json \
		--abi starknet_programs/fibonacci_abi.json
# This abi file is used for the `test_read_abi` test in contract_abi.rs

check-python-version:
	@python_version=`python -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")'`; \
	if python -c "import sys; exit(0) if (3, 8) <= sys.version_info < (3, 10) else exit(1)"; then \
		echo "Installed Python version ($$python_version) is correct"; \
	else \
		echo "Error: Installed Python version ($$python_version) is not 3.8 or 3.9"; \
		exit 1; \
	fi

build: compile-cairo compile-starknet
	cargo build --release --all

check: compile-cairo compile-starknet
	cargo check --all

deps: check-python-version 
	cargo install cargo-tarpaulin --version 0.23.1
	cargo install flamegraph --version 0.6.2
	python3 -m venv starknet-venv
	. starknet-venv/bin/activate && $(MAKE) deps-venv

clean:
	-rm -rf starknet-venv/
	-rm -f cairo_programs/*.json
	-rm -f starknet_programs/*.json
	-rm -f tests/*.json

clippy: compile-cairo compile-starknet
	cargo clippy --all --all-targets -- -D warnings

test: compile-cairo compile-starknet compile-abi
	cargo test

test-py: compile-cairo compile-starknet
	. starknet-venv/bin/activate
	cargo test -p starknet-rs-py --no-default-features --features embedded-python

coverage: compile-cairo compile-starknet
	cargo tarpaulin
	-rm -f default.profraw

heaptrack:
	./scripts/heaptrack.sh

flamegraph: compile-cairo compile-starknet
	CARGO_PROFILE_RELEASE_DEBUG=true cargo flamegraph --root --bench internals

