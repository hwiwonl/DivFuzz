#!/bin/bash

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

$DIR/scripts/bpatch.py $DIR/vmndh $DIR/tramp_afl.c $DIR/out && \
echo -ne '__AFL_SHM_ID\x00' >> $DIR/out/vmndh.afl &&
echo '[*] afl-patched vmndh built :)'