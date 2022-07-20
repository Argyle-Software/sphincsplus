#!/bin/bash
set -e

root=sphincsplus/ref

# Ensure script is run from KAT folder only
if [ ${PWD##*/} != "KAT" ]; then
  echo -e "KAT generation script must be run from the KAT folder\nPlease change directory"
fi

if [ ! -d "sphincsplus" ] ; then

  git clone https://github.com/sphincs/sphincsplus.git
  rm -rf sphincsplus/.git # stop git recognising it as a submodule

  # Keep old versions
  mv $root/PQCgenKAT_sign.c $root/PQCgenKAT_sign.c.orig
  mv $root/Makefile $root/Makefile.orig

else
  echo -e "Sphincs+ C git repository already exists\n"
fi

echo -e "## Build files are modified to output seed buffers ##\n"

echo -e '\n##### PQCgenKAT_sign.c diff #####\n'
diff $root/PQCgenKAT_sign.c.orig PQCgenKAT_sign.c || true

echo -e '\n\n##### Makefile diff #####\n'
diff $root/Makefile.orig Makefile || true
echo -e '\n\n'

# Move files
cp PQCgenKAT_sign.c $root/PQCgenKAT_sign.c
cp Makefile $root/Makefile

cd $root

HASH=("haraka" "sha2" "shake") 
MODE=("128f" "128s" "192f" "192s" "256s" "256f") 
THASH=("simple" "robust")

for hash in ${HASH[@]}; do
  for mode in ${MODE[@]}; do
    for thash in ${THASH[@]}; do

      echo Compiling: sphincs-$hash-$mode-$thash
      make -B PARAMS=sphincs-$hash-$mode THASH=$thash
      
      echo Building Known Answer Tests...
      ./PQCgenKAT_sign
      
      outfolder=${hash}_${mode}_${thash}
      echo  -e "KAT files written to $outfolder/tests/KAT \n\n"
      mv *.rsp ../../../$outfolder/tests/KAT/
      mv Seed* ../../../$outfolder/tests/KAT/
      rm *.req

    done
  done
done

exit 0


