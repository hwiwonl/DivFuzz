#!/bin/bash
FILE="bins/exploitme1"
INPUT="inputs"
OUTPUT="outputs"

afl-fuzz -i $INPUT -o $OUTPUT ./out/vmndh.afl -file $FILE -arg @@