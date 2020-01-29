# Chronos

> The world!

## Compile and run

```
git clone https://github.com/YangKeao/chronos.git
cd chronos
cargo run -- --pid $pid --tv_nsec_delta 1000000000 --tv_sec_delta 1000000000 --fake ./target/debug/libfake_clock_gettime.so
```

## Requirement

We need the target program dynamically linked with glibc, because we need `dlopen` in it.

## Implementation

### VDSO

First, we use `ptrace` to load `libfake_clock_gettime.so` into target program.

1. Parse `glibc` ELF and find `dlopen` and `dlsym` function.

2. Protect the current context (registers and ip instruction).

3. Modify ip instructions to `call` & `int`. And modify regs to call `dlopen` and `dlsym`.

Then we load fake image into target program and get `fake_clock_gettime` function address.

Finally we use `ptrace` to modify `clock_gettime` function in `[vdso]` part of the program. The modified `clock_gettime` will `jmp` to prepared `fake_clock_gettime` function.

As the `[vdso]` implementation has been destroyed, we cannot use vdso's `clock_gettime` in `fake_clock_gettime`. So we simulate it with pure syscall `clock_gettime`.

### Syscall

If your program call `clock_gettime` with pure syscall, method mentioned above will not work. You can pass `-e` argument to chronos to inject syscall directly.

If `-e` argument was passed to chronos, we will inject vdso to make sure all `clock_gettime` call will lead to syscall. And then we use `ptrace` to monitor syscall and modify the result of `clock_gettime`.

## TODO

1. PLT only mode. As most program linked with glibc will use glibc's binding `clock_gettime`, we can jmp to our fake function in PLT without destroy vdso's clock_gettime. And as every dynamic linked image has its own PLT, we can call `clock_gettime` directly in our fake function. It will be much simpler and faster than existing implementation.

2. Use ebpf to modify syscall. Use ebpf (like ethercflow/time-chaos does) to modify syscall rather than use `ptrace`. As `ptrace` way will interrupt at every syscall, it will have a much heavy influence on performance.

