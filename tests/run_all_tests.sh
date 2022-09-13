#!/bin/bash
set -e

# TODO: sanitiser rust flags

HASH=("haraka" "sha2" "shake") 
MODE=("f128" "s128" "f192" "s192" "s256" "f256") 
THASH=("simple" "robust")

for hash in ${HASH[@]}; do
  for mode in ${MODE[@]}; do
    for thash in ${THASH[@]}; do
      echo -e "\n\\n #### $hash-$mode-$thash ####"
      cargo +nightly test --release --features "$hash $mode $thash KAT"
    done
  done
done

exit 0