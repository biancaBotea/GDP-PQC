#!/bin/bash

for i in {0..5} 
do 
    for j in {0..6} 
    do
        sleep 5
        valgrind --tool=massif --heap=no --stacks=yes --detailed-freq=100 ./client $i $j
    done
done
