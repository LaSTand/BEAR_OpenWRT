# This files downloads snort rules auto-update scripts

#!/bin/ash

DATE1=`date +%g%m%d`

F_LOC="./scripts/""$DATE1""_update.sh"

if [ -e "$F_LOC" ]
then
	echo "Update script already exist!"
else
	wget http://www.fossa.kr/~bear/conf_files/"$DATE1"_update.sh -P ./scripts/
fi

cd ./scripts/
./"$DATE1"_update.sh
