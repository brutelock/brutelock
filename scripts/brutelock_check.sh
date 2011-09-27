#! /bin/sh

# Brutelock Check script
#
# This script should be setup to run on a cron
# every 15-30 minutes or so, to ensure that the brutelock
# program is running
#
# If you would like to receive an email notification when this happens
# uncomment the "EMAIL" line and add the address that you wish to receive 
# the notification at.  You will also need to uncomment the "echo" line 
# inside the if statement below.
#

#EMAIL='YOUR_EMAIL_HERE'
BRUTELOCK_PATH='/usr/local/brutelock/bin'
RESULT=`ps ax | grep -v grep | grep brutelockd`

if [ -z "$RESULT" ]
then
   echo "brutelockd is not running"
   #echo "brutelockd has stopped running.  A restart has been attempted." | mail -s "brutelockd failed" $EMAIL

   # Now lets try to restart
   $BRUTELOCK_PATH/brutelockd
fi

