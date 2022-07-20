#!/bin/bash

# remove Cargo.toml note
# for dir in h* sh* ; do
#   sed -i '6d' $dir/Cargo.toml
# done

# Copy tests dir
# for dir in h* sh* ; do
#   cp -r tests $dir
# done

# Replace test import
# for dir in h* sh* ; do
#   echo "use sphincs_$dir::*"
#   sed -i "3i use sphincs_$dir::*;" $dir/tests/kat.rs
# done

# Move lib file
# for dir in h* sh* ; do
#   cp lib.rs $dir/src/
# done

# # List all folders
# for dir in h* sh* ; do
#   echo \"$dir\",  
# done