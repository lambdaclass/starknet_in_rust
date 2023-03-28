#!/usr/bin/env sh
# hyperfine --warmup 5 \
# 	    -n "cairo-lang fib 15k" "pytest bench_integration.py::test_invoke" \
# 	    -n "starknet_in_rust fib 15k" "cargo test testing::bench_integration::test_invoke --release"
hyperfine -N -w 3 -r 100 'pytest bench_integration.py::test_invoke' 'cargo test testing::bench_integration::test_invoke --release'
