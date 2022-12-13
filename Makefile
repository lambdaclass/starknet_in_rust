.PHONY: build check test clippy compile_cairo clean
	
build: 
	cargo build --release

check: 
	cargo check 

compile_cairo:
	cairo-compile cairo_syscalls/syscalls.cairo --output cairo_syscalls/syscalls.json

clean: 
	rm cairo_syscalls/*json

clippy:
	cargo clippy  -- -D warnings

test: 
	cargo test
