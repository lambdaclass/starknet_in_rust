#!/usr/bin/env sh
hyperfine -N -w 3 -r 5 \
	    -n "cairo-lang (CPython) fib 15k" "pytest bench_integration.py::test_fibonacci" \
	    -n "starknet_in_rust fib 15k" "./target/release/fibonacci"
