# Run rebar ct with memory address sanitizer

## Prepare

Build otp with different emu types.

## Run

Supported runs are

- sanitizer-check
- debug-check
- valgrind-check

### Run all tests

Just take `sanitizer-check` as examples 

``` sh
tools/run/bin/sanitizer-check all
```

### Run one test in the suite
``` sh
tools/run/bin/sanitizer-check --suite=SUITE --case=CASE
```

### Run CT test cases one by one
``` sh
tools/run/bin/sanitizer-check one_by_one
```

## Check coredumps

Debug emu generates coredump when it isn't happy,
to check the latest core file with gdb use following

``` sh
tools/run/bin/debug-gdb-core 
```

