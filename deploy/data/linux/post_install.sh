#!/bin/bash

# IFW's administrator operation already runs as root. Do not depend on a
# second privilege escalator being installed in that case.
if [ "$(id -u)" -eq 0 ]; then
        sudo() { command "$@"; }
fi

APP_NAME=AmneziaVPN
LOG_FOLDER=/var/log/$APP_NAME
LOG_FILE="$LOG_FOLDER/post-install.log"
APP_PATH=/opt/$APP_NAME

if ! test -d $LOG_FOLDER; then
        sudo mkdir -p $LOG_FOLDER || exit 1
        echo "AmneziaVPN log dir created at /var/log/"
fi

if ! test -f $LOG_FILE; then
        touch $LOG_FILE
        echo "AmneziaVPN log file created at /var/log/AmneziaVPN/post-install.log"
fi

date > $LOG_FILE
echo "Script started" >> $LOG_FILE
sudo killall -9 $APP_NAME 2>> $LOG_FILE

if command -v steamos-readonly &> /dev/null; then
        sudo steamos-readonly disable >> $LOG_FILE
        echo "steamos-readonly disabled" >> $LOG_FILE
fi

# Stop also waits for an already-deactivating service. Never replace its unit
# or finish installation while the durable DNS restore barrier is pending.
UNIT_STATE=$(sudo systemctl show "$APP_NAME" -p LoadState --value) || exit 1
if [ "$UNIT_STATE" != "not-found" ]; then
	sudo systemctl stop "$APP_NAME" >> "$LOG_FILE" || exit 1
	ACTIVE_STATE=$(sudo systemctl show "$APP_NAME" -p ActiveState --value) || exit 1
	[ "$ACTIVE_STATE" = "inactive" ] || exit 1
fi

sudo chmod -R a-w $APP_PATH/

sudo cp $APP_PATH/$APP_NAME.service /etc/systemd/system/ >> $LOG_FILE || exit 1
sudo systemctl daemon-reload >> $LOG_FILE || exit 1

sudo systemctl start $APP_NAME >> $LOG_FILE || exit 1
sudo systemctl enable $APP_NAME >> $LOG_FILE || exit 1
sudo ln -sf $APP_PATH/bin/$APP_NAME /usr/local/sbin/$APP_NAME >> $LOG_FILE
sudo ln -sf $APP_PATH/bin/$APP_NAME /usr/local/bin/$APP_NAME >> $LOG_FILE

echo "user desktop creation loop started" >> $LOG_FILE
sudo cp $APP_PATH/$APP_NAME.desktop /usr/share/applications/ >> $LOG_FILE
sudo cp $APP_PATH/$APP_NAME.png /usr/share/pixmaps/ >> $LOG_FILE
sudo chmod 555 /usr/share/applications/$APP_NAME.desktop >> $LOG_FILE

echo "user desktop creation loop ended" >> $LOG_FILE

if command -v steamos-readonly &> /dev/null; then
        sudo steamos-readonly enable >> $LOG_FILE
        echo "steamos-readonly enabled" >> $LOG_FILE
fi

date >> $LOG_FILE
echo "Service status:" >> $LOG_FILE
sudo systemctl status $APP_NAME >> $LOG_FILE
date >> $LOG_FILE
echo "Script finished" >> $LOG_FILE
sudo systemctl is-active --quiet "$APP_NAME" || exit 1
sudo systemctl is-enabled --quiet "$APP_NAME" || exit 1
exit 0
