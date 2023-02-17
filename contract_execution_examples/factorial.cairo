%lang starknet

// factorial(n) =  n!
@external
func factorial(n) -> (result: felt) {
    if (n == 1) {
        return (n,);
    }
    let (a) = factorial(n - 1);
    return (n * a,);
}

func main() {
    return ();
}