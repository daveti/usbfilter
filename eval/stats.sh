#!/bin/bash

file=$1

echo
echo $file
echo

# Average
awk '{ total += $1; } END { print "Average: " total/(NR) }' $file

# Min and Max
awk 'NR == 1 { max=$1 ; min=$1 } $1 >= max { max = $1 } $1 <= min {min = $1}
END { print "Min: "min; print "Max: "max }' $file

# Standard deviation
awk '{ sum+=$1; sumsq+=$1*$1 } 
END { print "Standard deviation: " sqrt(sumsq/NR - (sum/NR)**2) }' $file 

# Median
sort $file | awk '{ count[NR] = $1 } 
END { if (NR % 2) {print "Median: " count[(NR + 1) / 2]
} else { print "Median: " (count[(NR / 2)] + count[(NR / 2) + 1]) / 2.0 }}' 
