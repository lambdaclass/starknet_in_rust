compile_cairo:
	cairo-compile cairo_syscalls/syscalls.cairo --output cairo_syscalls/syscalls.json
	
build: 
	cargo build --release

clean: 
	rm cairo_syscalls/*json

clippy:
	cargo clippy  -- -D warnings

test: 
	cargo test
