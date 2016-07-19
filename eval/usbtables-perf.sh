#!/bin/bash

# The script to benchmark usbtables
# NOTE: Xie is not happy with this script.
# Feb 14, 2016
# daveti

USBTABLES_CMD=/root/git/usbfilter/usbtables/usbtables
PERF_LOG=./usbtables.perf
TEST_NUM=100
RULE_PRELOAD=false

# Preload rules
if [ "$RULE_PRELOAD" = true ]
then
	echo "preload rules..."
	$USBTABLES_CMD -a logitech-headset -v ifnum=2,product="Logitech USB Headset",manufacturer=Logitech -k direction=1 -t drop > $PERF_LOG
	sleep 5
	$USBTABLES_CMD -a teensy1 -v ifnum=2,manufacturer=Teensyduino,serial=1509380 -t drop >> $PERF_LOG
	sleep 5
	$USBTABLES_CMD -a teensy2 -v ifnum=3,manufacturer=Teensyduino,serial=1509380 -t drop >> $PERF_LOG
	sleep 5
	$USBTABLES_CMD -a teensy3 -v ifnum=4,manufacturer=Teensyduino,serial=1509380 -t drop >> $PERF_LOG
	sleep 5
	$USBTABLES_CMD -a mymouse -v busnum=1,devnum=4,portnum=2,devpath=1.2,product="USB Optical Mouse",manufacturer=PixArt -k type=1 -t allow >> $PERF_LOG
	sleep 5
	$USBTABLES_CMD -a mykeyboard -v busnum=1,devnum=3,portnum=1,devpath=1.1,product="Dell USB Entry Keyboard",manufacturer=DELL -k type=1 -t allow >> $PERF_LOG
	sleep 5
	$USBTABLES_CMD -a noducky -k type=1 -t drop >> $PERF_LOG
	sleep 5
	$USBTABLES_CMD -a nodataexfil -v manufacturer=Kingston -l name=block_scsi_write -t drop >> $PERF_LOG
	sleep 5
	$USBTABLES_CMD -a daveskype -o uid=1001,comm=skype -v serial=B4482A20 -t allow >> $PERF_LOG
	sleep 5
	$USBTABLES_CMD -a nowebcam -v serial=B4482A20 -t drop >> $PERF_LOG
	sleep 5
	echo "=========Preload Done=============" >> $PERF_LOG
else
	echo "=========Skip Preload============" > $PERF_LOG
fi

# Start perf
echo "start benchmark..."
COUNTER=0
while [ $COUNTER -lt $TEST_NUM ]
do
		echo "test: $COUNTER"
		$USBTABLES_CMD -a perf_rule -v product=daveti,manufacturer=daveti -t drop -i >> $PERF_LOG
		sleep 2
		$USBTABLES_CMD -r perf_rule > /dev/null
		sleep 2
		let COUNTER=COUNTER+1 
		echo "==========test $COUNTER===========" >> $PERF_LOG
done
echo "done..."
