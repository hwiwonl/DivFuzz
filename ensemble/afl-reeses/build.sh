#!/bin/bash

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

$DIR/scripts/bpatch.py $DIR/reeses $DIR/tramp_reeses.c $DIR/out && \
echo -ne '__AFL_SHM_ID\x00' >> $DIR/out/reeses.afl &&
echo '[*] afl-patched reeses built :)'