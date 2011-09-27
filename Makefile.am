AUTOMAKE_OPTIONS=foreign

AM_CFLAGS="-DPREFIX=\"$(prefix)\""
LDADD=-lsqlite3 -lxml2 -lcurl

myexec_SCRIPTS=brutelock_check.sh createdb.sh initscript
myexecdir=$(bindir)
bin_PROGRAMS=brutelockd brutelocksync

brutelockd_SOURCES=brutelockd.c brutelock.c brutelocksync.c db.c
brutelocksync_SOURCES=syncmain.c brutelock.c brutelocksync.c db.c
noinst_HEADERS=brutelock.h brutelocksync.h db.h

EXTRA_DIST=INSTALL README LICENSE conf/brutelock.conf conf/whitelist \
    scripts/brutelock_check.sh scripts/createdb.sh scripts/initscript \
	brutelock.logrotate

brutelock_check.sh:
	sed -i -e "s,BRUTELOCK_PATH=.*,BRUTELOCK_PATH='$(bindir)',g" scripts/brutelock_check.sh 

createdb.sh:
	sed -i -e "s,prefix=.*,prefix=$(prefix)," scripts/createdb.sh

initscript:
	sed -i -e s,/.*/bin/brutelockd,$(prefix)/bin/brutelockd, scripts/initscript

all-local: logrotate


if LOGROTATE 
LOGROTATE_INTERVAL=0
else
LOGROTATE_INTERVAL=1
endif

# Put the correct path to the log file in the logrotate conf file
logrotate:
	sed -i -e 's/LOG_ROTATE_INTERVAL=.*/LOG_ROTATE_INTERVAL=$(LOGROTATE_INTERVAL)/' conf/brutelock.conf

TARGET=$(DESTDIR)$(prefix)

install-data-hook: install-logrotate
	-mkdir $(TARGET)/conf
	-mkdir $(TARGET)/logs
	-mkdir $(TARGET)/db
	-mkdir $(TARGET)/scripts
	touch $(TARGET)/logs/brutelock.log
	cp conf/brutelock.conf $(TARGET)/conf/brutelock.conf
	cp conf/whitelist $(TARGET)/conf/whitelist
	cp scripts/brutelock_check.sh $(TARGET)/scripts/brutelock_check.sh
	cp scripts/createdb.sh $(TARGET)/scripts/createdb.sh
	cp scripts/initscript $(TARGET)/scripts/initscript
	$(TARGET)/scripts/createdb.sh

if LOGROTATE 
install-logrotate:
	cp brutelock.logrotate /etc/logrotate.d/brutelock
else
install-logrotate:
endif
