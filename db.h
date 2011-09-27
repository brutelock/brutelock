#ifndef __DB_H__
#define __DB_H__

#define DATABASE            PREFIX"/db/brutelock.db"

void openDBConnection(char *database);
void closeDBConnection();
void cleanDB();
void flushBlockedTable();
void logAuthFailure(char *host, char *service);
int hostAlreadyBlocked(char *host);
int getHostLoginAttempts(char *host, char *service);
void logBlocked(char *host);

#endif
