#!/bin/bash
set -e

# TODO: Use avx/aes builds for each hash type, it's a slow process in ref. 
root=sphincsplus/ref

# Ensure script is run from KAT folder only
if [ ${PWD##*/} != "tests" ]; then
  echo -e "
KAT file generation script must be run from the tests folder
Please move into the correct working directory first \n"
  exit 1
fi

if [ ! -d "sphincsplus" ] ; then

  git clone https://github.com/sphincs/sphincsplus.git
  rm -rf sphincsplus/.git # remove pesky git submodule

  # Keep old versions for comparison
  mv $root/PQCgenKAT_sign.c $root/PQCgenKAT_sign.c.orig
  mv $root/Makefile $root/Makefile.orig

else
  echo -e "Sphincs+ C git repository already exists\n"
fi

echo -e "## Modified build files output seed buffers ##\n"

echo -e '\n### PQCgenKAT_sign diff ###'
diff $root/PQCgenKAT_sign.c.orig PQCgenKAT_sign.c || true # avoid script exit

echo -e '\n### Makefile diff ###'
diff $root/Makefile.orig Makefile || true

# Move modified files
cp PQCgenKAT_sign.c $root/PQCgenKAT_sign.c
cp Makefile $root/Makefile

cd $root

# Variants
HASH=("shake" "haraka" "sha2") 
MODE=("128f" "128s" "192f" "192s" "256s" "256f") 
THASH=("simple" "robust")

for hash in ${HASH[@]}; do
  for mode in ${MODE[@]}; do
    for thash in ${THASH[@]}; do

      echo -e "\n\nCompiling: sphincs-$hash-$mode-$thash"
      make -B PARAMS=sphincs-$hash-$mode THASH=$thash
      
      echo -n "Building known answer tests..."
      ./PQCgenKAT_sign
      
      mv *.rsp ../../KAT/
      mv Seed* ../../KAT/
      rm *.req
      echo " done."

    done
  done
done
exit 0


