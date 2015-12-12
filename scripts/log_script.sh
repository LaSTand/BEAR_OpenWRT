# This script will runs at 23:59
# Compress all the logs and store it.

#!/bin/sh

DATE=`date +%g%m%d`
DATE2=`date`
L_DIR="/mnt/log"

echo "======================================"
echo " Log Compession : "$DATE2""
echo "======================================"

tar -cvf "$L_DIR"/* "$L_DIR"/log"$DATE".tar

# More script update are need
