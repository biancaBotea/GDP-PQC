#!/bin/bash

for i in {0..5}
do 
    for j in {0..6}
    do
        sleep 2
        valgrind --tool=massif --heap=no --stacks=yes --detailed-freq=100 ./server $i
    done
done
