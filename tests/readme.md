# Testing

To run the tests on an individual mode: 
```shell
cargo test --features "haraka f128 simple" --release  
```

To run a shorter subset (10 test vectors) use the env variable SPHINCS_FAST_TEST
```shell
SPHINCS_FAST_TEST=1 cargo test --features "haraka f128 simple" --release
```

it is recommended to run tests with release builds, even when using the subset.

To go through the full matrix of all modes use the [test_matrix.sh](./test_matrix.sh) file.



## Known Answer Tests

Test vectors and seeds are contained in the `KAT` folder. 
To create them yourself run [build_kat_files.sh](./build_kat_files.sh). The original `PQCgenKAT_sign.c` has been modified to write the deterministic seed buffers for each security level into files.

To compare the modifications:
```shell
diff --color <(curl https://raw.githubusercontent.com/sphincs/sphincsplus/master/ref/PQCgenKAT_sign.c) ./PQCgenKAT_sign.c
```