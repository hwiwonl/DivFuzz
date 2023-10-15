#!/bin/bash

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

$DIR/scripts/bpatch.py $DIR/clemency-emu $DIR/tramp_clemency.c $DIR/out && \
echo -ne '__AFL_SHM_ID\x00' >> $DIR/out/clemency-emu.afl &&
echo '[*] afl-patched clemency built :)'
