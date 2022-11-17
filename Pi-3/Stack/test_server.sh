#!/bin/bash

for i in {0..6}
do 
    for j in {0..5}
    do
        sleep 1
        valgrind --tool=massif --heap=no --stacks=yes --detailed-freq=100 ./server $i
    done
done