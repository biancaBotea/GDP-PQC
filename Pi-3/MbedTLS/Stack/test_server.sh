#!/bin/bash

for i in {0..3}
do
    sleep 1
    valgrind --tool=massif --heap=no --stacks=yes --detailed-freq=100 ./server $i
done
