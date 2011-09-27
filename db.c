#include <stdio.h>

#include <sqlite3.h>

#include "db.h"

sqlite3 *db;                // Global database handle

/**
 * Open a connection to the given SQLite database
 */
void openDBConnection(char *database) {
    if (sqlite3_open(database, &db) != SQLITE_OK) {
        errx(1, "Error opening database %s: %s\n", 
            database, sqlite3_errmsg(db));
    }
}

/**
 * Close the connection to the SQLite database if its open
 */
void closeDBConnection() {
    if (db)
        sqlite3_close(db);
}

/**
 * Clears out all log entries older than 30 days
 */
void cleanDB() {
    execSQL(
        "DELETE FROM ip_log "
        "WHERE insert_dttm < datetime('now', '-1 days') "
            "AND ip NOT IN "
                "(SELECT ip FROM BLOCKED) "
            "OR insert_dttm < datetime('now', '-30 days')");
}

/**
 * Clears the table of ips that have been locally blocked.
 */
void flushBlockedTable() {
    execSQL("DELETE FROM blocked");
}

/**
 * Logs the authentication failure to the ip_log table in the database.
 */
void logAuthFailure(char *host, char *service) {
    char cmd[BUFSIZ];

    snprintf(
        cmd, BUFSIZ,
        "INSERT INTO ip_log (ip, log_type, service, insert_dttm) "
        "VALUES ('%s', 'auth fail', '%s', DATETIME('NOW'))",
        host, service
    );

    execSQL(cmd);
}

/**
 * Returns 1 if the given host is already in the blocked table and 0 if not.
 */
int hostAlreadyBlocked(char *host) {
    char cmd[BUFSIZ];

    snprintf(cmd, BUFSIZ, "SELECT 1 FROM blocked WHERE ip = '%s'", host);
    return execSQL(cmd);
} 

/**
 * Gets the number failed authentication attempts from the database for the
 * given host. 
 */
int getHostLoginAttempts(char *host, char *service) {
    char cmd[BUFSIZ];

    snprintf(cmd, BUFSIZ, 
        "SELECT COUNT(ip) FROM ip_log WHERE ip = '%s'"
        "AND service = '%s'", host, service);
    return execSQL(cmd);
}

/**
 * Inserts an entry into the blocked database for the given host.
 */
void logBlocked(char *host) {
    char cmd[BUFSIZ];

    snprintf(cmd, BUFSIZ, "INSERT INTO blocked VALUES ('%s')", host);
    execSQL(cmd);
}

/**
 * SQLite3 callback that stores the first response value into the user argument.
 */
static int dbCallback(void *user, int argc, char **argv, char **azColName){
    *((int *)user) = atoi(argv[0]);
    return 0;
}

/**
 * Executes the given SQL statement against the open SQLite database and
 * returns the response if there is one. The return value expected can only 
 * be a single value.
 */
int execSQL(char *cmd) {
    char *errmsg = NULL;
    int count = 0;

    if (sqlite3_exec(db, cmd, dbCallback, (void *)&count, &errmsg) 
            != SQLITE_OK) {
        fprintf(stderr, "Failed to execute sql '%s'\nReason: %s\n", 
            cmd, sqlite3_errmsg(db));        
        if (errmsg) {
            fprintf(stderr, "Error: %s\n", errmsg);
            sqlite3_free(errmsg);
        }
        exit(1);
    }

    return count;
}

