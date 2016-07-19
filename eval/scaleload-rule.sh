#!/bin/bash

# The script to preload 90 rules for scalability testing
# NOTE: Xie is not happy with this script.
# Feb 14, 2016
# daveti

USBTABLES_CMD=/root/git/usbfilter/usbtables/usbtables
PERF_LOG=./scaleload.perf
PERF_LOG2=./scaletest.perf
LOAD_NUM=80
TEST_NUM=100
COUNTER=0
COUNTER2=0

echo "start scaleloading..."
echo "===========Scaleloading Rules==============" > $PERF_LOG

# Scale load
while [ $COUNTER -lt $LOAD_NUM ]
do
		echo "scale: $COUNTER"
		$USBTABLES_CMD -a scale_rule$COUNTER -v product=daveti$COUNTER,manufacturer=daveti$COUNTER -t drop -i >> $PERF_LOG
		sleep 2
		let COUNTER=COUNTER+1 
		echo "==========test $COUNTER===========" >> $PERF_LOG
done

# Just loading
echo "done...without testing"
exit

# Start test
echo "start scaletesting..."
echo "============Scale Testing==============" > $PERF_LOG2
COUNTER2=0
while [ $COUNTER2 -lt $TEST_NUM ]
do
		echo "test: $COUNTER2"
		$USBTABLES_CMD -a perf_rule -v product=xie,manufacturer=xie -t drop -i >> $PERF_LOG2
		sleep 2
		$USBTABLES_CMD -r perf_rule > /dev/null
		sleep 2
		let COUNTER2=COUNTER2+1 
		echo "==========test $COUNTER2===========" >> $PERF_LOG2
done

echo "done..."
