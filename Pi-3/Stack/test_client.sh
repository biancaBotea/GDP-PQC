#!/bin/bash

for i in {0..6} 
do 
    for j in {0..5} 
    do
        sleep 5
        valgrind --tool=massif --stacks=yes ./client $i $j
    done
done