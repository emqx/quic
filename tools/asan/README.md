# Run rebar ct with memory address sanitizer

## Prepare

Build otp with debug type: asan

## Run

### Run all tests

``` sh
tools/asan/bin/sanitizer-check all
```

### Run one test in the suite
``` sh
tools/asan/bin/sanitizer-check --suite=SUITE --case=CASE
```

### Run CT test cases one by one
``` sh
tools/asan/bin/sanitizer-check one_by_one
```
