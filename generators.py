def execute(n: int):
    print(f'[NATIVE] Entering Cairo Native (n = {n})')

    if n > 0:
        print(f'[NATIVE] Calling itself recursively (n = {n})')
        yield ['call_contract', n - 1]

    print(f'[NATIVE] Exiting Cairo Native (n = {n})')


def run_contract(n: int):
    # NativeExecutor
    execution_iter = execute(n)

    try:
        while True:
            print('Borrowing NativeExecutor')
            syscall = next(execution_iter)
            print('Releasing NativeExecutor')

            if syscall[0] == 'call_contract':
                run_contract(syscall[1])
    except StopIteration:
        print('Done')


if __name__ == '__main__':
    run_contract(1)
