#!/bin/sh

# Create or bring the brutelock database up to the latest version

prefix=/usr/local/brutelock
db=$prefix/db/brutelock.db

if [ ! -e $db ]; then
    # Create the databases from scratch
    sqlite3 $db "CREATE TABLE blocked (ip VARCHAR(15))";
    sqlite3 $db "CREATE TABLE ip_log (ip VARCHAR(15), log_type VARCHAR(40), service VARCHAR(40), insert_dttm TIMESTAMP)";
    sqlite3 $db "CREATE TABLE version (version integer)";
    sqlite3 $db "INSERT INTO version VALUES (1)";
else
    # Figure out which version we are at and aply the necessary upgrades
    version=$(sqlite3 $db "SELECT version FROM version");
   
    if [ $? -eq 1 ]; then
        sqlite3 $db "ALTER TABLE ip_log ADD COLUMN service VARCHAR(40)";
        sqlite3 $db "CREATE TABLE version (version integer)";
        sqlite3 $db "INSERT INTO version VALUES (1)";
    else
        exit 0;
    fi; 
fi

exit 0;
