#!/bin/sh
gcc in.c -o in
mkdir -p out/assets
cp *.h out/assets
~/defkor/emupatch/scripts/bpatch.py ./in ./patch.c ./out
gcc fuzz.c -o fuzz -ldl
