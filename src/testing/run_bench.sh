#!/usr/bin/env sh
hyperfine \
	    -n "cairo-lang 1k" "pytest bench_integration.py::test_invoke1000" \
	    -n "starknet_in_rust 1k" "cargo test testing::bench_integration::test_invoke1000 --release"
		
hyperfine \
	    -n "cairo-lang 5k" "pytest bench_integration.py::test_invoke5000" \
	    -n "starknet_in_rust 5k" "cargo test testing::bench_integration::test_invoke5000 --release"

hyperfine \
	    -n "cairo-lang 10k" "pytest bench_integration.py::test_invoke10000" \
	    -n "starknet_in_rust 10k" "cargo test testing::bench_integration::test_invoke10000 --release"
		

