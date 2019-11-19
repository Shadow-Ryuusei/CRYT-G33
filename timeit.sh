#!/bin/bash

echo "g33-30"
time (
	for (( i=1; i<2000; i++ )); do
 		./g33-30
 	done
)

echo "g33-8"
time (
	for (( i=1; i<2000; i++ )); do
 		./g33-8
 	done
)

echo "g33 0"
time (
	for (( i=1; i<2000; i++ )); do
 		echo "0" | ./g33
 	done
)

echo "g33 1"
time (
	for (( i=1; i<2000; i++ )); do
 		echo "1" | ./g33
 	done
)
