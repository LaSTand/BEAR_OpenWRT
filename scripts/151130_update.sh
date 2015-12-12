# This is for crontab script

# wget https://snort.org/rules/snort/snortrules-snapshot-2967.tar.gz?oinkcode=<oinkcode>
# tar -xvzf snortrules-snapshot-<version>.tar.gz -C /etc/snort/rules
#
# 22042326bd8f15d7f2d722e9c8d639c0158085ab : Oinkcode / lastand73@gmail.com
#
# Snort rules update script
#

DATE1=`date +%g%m%d`
DATE2=`date`

echo ======================================== >> ./snort_update-$DATE.txt
echo "Rule update Started at $DATE2" >> ./snort_update-$DATE.txt
echo ======================================== >> ./snort_update-$DATE.txt

# Delete old snapshot files 
rm -rf ./snortrules-snapshot*

# Download new snapshot file from snort org. 
wget https://snort.org/rules/snortrules-snapshot-2976.tar.gz?oinkcode=22042326bd8f15d7f2d722e9c8d639c0158085ab -P ./snortrules-snapshot-2976.tar.gz >> ./snort_update-$DATE.txt
# tar -xzvf snortrules-snaptshot*.tar.gz -C ./

echo ======================================== >> ./snort_update-$DATE.txt
echo "Rules update successed at $DATE2" >> ./snort_update-$DATE.txt
echo ========================================>> ./snort_update-$DATE.txt
