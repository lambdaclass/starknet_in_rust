%lang starknet
// from starkware.cairo.common.cairo_builtins import HashBuiltin

// @storage_var
// func _counter() -> (res: felt) {
// }

func main() {
    // Call fib(1, 1, 10).
    let result: felt = fib(1, 1, 10);

    // Make sure the 10th Fibonacci number is 144.
    assert result = 144;
    ret;
}

// @external
// func f{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr}() -> (res:felt) {
//      _counter.write(42);
//      return _counter.read();
// }

@external
func fib(first_element, second_element, n) -> (res: felt) {
    jmp fib_body if n != 0;
    tempvar result = second_element;
    return (second_element,);

    fib_body:
    tempvar y = first_element + second_element;
    return fib(second_element, y, n - 1);
}
