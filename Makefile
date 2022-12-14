.PHONY: build check test clippy compile_cairo clean
	
build: 
	cargo build --release

check: 
	cargo check 

deps:
	pip install cairo-lang==0.10.1 
	python3 -m venv starknet-in-rs-venv
	. starknet-in-rs-venv/bin/activate && \
	pip install cairo_lang==0.10.1 && \
	deactivate

clean: 
	rm cairo_syscalls/*json

clippy:
	cargo clippy  -- -D warnings

venv-test:
	. starknet-in-rs-venv/bin/activate && \
	cairo-compile cairo_syscalls/syscalls.cairo --output cairo_syscalls/syscalls.json
	cargo test
	deactivate

test:
	cargo test
