#!/bin/bash

for i in {0..6}
do 
    for j in {0..5}
    do
        sleep 1
        valgrind --tool=massif --stacks=yes ./server $i
    done
done