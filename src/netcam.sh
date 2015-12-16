#!/bin/sh -e
#
# /etc/init.d/netcam: Start the network camera 
#
### BEGIN INIT INFO
# Provides:	  netcam
# Required-Start: $local_fs $syslog $remote_fs
# Required-Stop: $remote_fs
# Default-Start:  2 3 4 5
# Default-Stop: 0 1 6
# Short-Description: Start simple network camera
# Description: Stream MJPEG from raspberry pi
### END INIT INFO

NAME=netcam
PATH_BIN=/bin:/usr/bin:/sbin:/usr/sbin:/usr/local/bin
DAEMON=/usr/local/bin/netcam
PIDFILE=/var/run/$NAME.pid
DEFAULTS=/etc/default/$NAME
DESC="network camera daemon"
ENV="env -i LANG=C PATH=$PATH_BIN"

. /lib/lsb/init-functions

test -x $DAEMON || exit 0

RET=0

# load v4l2 modules
modprobe bcm2835_v4l2 max_video_width=1920 max_video_height=1080

case "$1" in
  start) 
    log_daemon_msg "Starting $DESC" "$NAME" 
    if start-stop-daemon --start --oknodo --exec $DAEMON -b; then
            log_end_msg 0
        else
            log_end_msg 1
            RET=1
        fi
     ;;
   stop)
    log_daemon_msg "Stopping $DESC" "$NAME"
    if start-stop-daemon --stop --oknodo --exec $DAEMON --retry 30 ; then
        log_end_msg 0
    else
        log_end_msg 1
        RET=1
    fi
    ;;
   *) 
    echo "Usage: /etc/init.d/$NAME {start|stop}"
    RET=1
    ;;
esac


exit $RET
