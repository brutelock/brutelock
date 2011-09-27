/* Copyright (C) 2008-2009 Intuitive Reason, Inc. info@intuitivereason.com
 *
 * The program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU General Public
 * License along with this program; see the file LICENSE.  If not,
 * write to the Free Software Foundation, Inc., 59 Temple Place - Suite 330,
 * Boston, MA 02111-1307, USA.  
 */

#ifndef __BRUTELOCK_H__
#define __BRUTELOCK_H__

#include <libxml/parser.h>
#include <regex.h>

#define CONF_FILE               PREFIX"/conf/brutelock.conf"
#define LOG_FILE                PREFIX"/logs/brutelock.log"

// Firewall types
#define IPTABLES    0x01

// Regular expression string and its compiled form, along with other parameters
// associated with the log file pattern
struct regexList {
    char *regexString;
    regex_t regex;
    int maxAttempts;
    char *service;

    struct regexList *next;
};

// Information about the different logs that can be handeled
struct logType {
    char *name;
    struct regexList *failedPatterns;

    // Last size read of the log file 
    size_t osize;

    struct logType *next;
};

// Configuration variables
extern char key[BUFSIZ];        // Key sent in the url
extern int firewall;            // Firewall being used
extern char chainName[BUFSIZ];  // iptables chain name
extern int syncInterval;        // How often in minutes to sync with the server 
extern int maintInterval;       // How often in days to clean db
extern int logRotateInterval;   // How often in days rotate logs 
extern struct logType *logs;    // Log files to be handled 
extern char centralServer[BUFSIZ];  // Where to send updates to

void blockHost(char *ip);
void parseConfFile();
void logEventToLogFile(char *event);
void logXMLMessage(xmlNodePtr node, char *logMsg);
xmlNodePtr skipXMLWhiteSpace(xmlNodePtr node);
void initWebQuerier();
void stopWebQuerier();
char *getWebResponse(char *url);
void checkFirewall();
void sendSyncSummaryEmail(char **ips, int numIPs);

#ifdef DEBUG
/**
 * Prints debug statements.
 */
void DBG(char *fmt, ... );
#else
#define DBG(fmt, ...)   0
#endif

#endif
