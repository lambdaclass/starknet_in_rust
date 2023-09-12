#!/usr/bin/env sh
hyperfine -N -w 3 -r 5 \
	    -n "starknet_in_rust fib 15k" "./target/release/fibonacci"
