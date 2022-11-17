#!/bin/bash

FILES="./massif.out.*"

for f in $FILES
do
    sed -n -e 2p $f
    grep "mem_stacks_B=" $f | sed s/mem_stacks_B=// | sort -nr | head -n1
    printf "\n"
done