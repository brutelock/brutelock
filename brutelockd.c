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

#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <malloc.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <err.h>
#include <signal.h>
#include <string.h>
#include <netdb.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <time.h>
#include <strings.h>
#include <regex.h>
#include <getopt.h>

#include <libxml/xmlmemory.h>
#include <libxml/parser.h>

#include "brutelock.h"
#include "brutelocksync.h"
#include "db.h"

#define WHITELIST           PREFIX"/conf/whitelist"

#define SLEEP_INTERVAL      250000   // 250ms sleeps between each log check

struct ipList {
    char **list;
    int numEntries;
};

struct ipList whitelist;    // Hosts whos failed authentication attempts we will
                            // be ignored.
int pidFileCreated = 0;     // True when we have created the pid run file

/**
 * String comparison with wildcards. * stands for any number of characters,
 * and ? stands for a single character.
 *
 * @param wild      String with wildcards in it
 * @param string    String with no wildcards 
 * @return 1 on match, 0 if no match
 */
int wildcmp(char *wild, char *string) {
    char *cp, *mp;

    // Match the strings character by character until we find a *
    while ((*string) && (*wild != '*')) {
        if ((*wild != *string) && (*wild != '?')) {
            return 0;
        }

        wild++;
        string++;
    }

    while (*string) {
        if (*wild == '*') {
            // If we are at the end of the wild string then we are done
            if (!*++wild) {
                return 1;
            }

            mp = wild;
            cp = string + 1;
        }
        else if ((*wild == *string) || (*wild == '?')) {
            wild++;
            string++;
        } 
        else {
            wild = mp;
            string = cp++;
        }
    }

    // Ignore any *s that are left over
    while (*wild == '*') {
        wild++;
    }

    // If we are at the end of the wild string then the two match
    return !*wild;
}

/**
 * Returns 1 if the ip is in the whitelist and 0 otherwise.
 */
int inWhiteList(char *ip) {
    int i;

    for (i = 0; i < whitelist.numEntries; i++ ) {
        if (wildcmp(whitelist.list[i], ip) != 0)
            return 1;
    }  

    return 0;
}

/**
 * Loads the ip list stored in the given file and stores it in the whitelist
 * global variable. Each line should contain an ip in dotted quad notation
 */
void loadWhitelist(char *file) {
    FILE *fd;
    char buf[32];

    DBG("Loading whitelist %s\n", file);

    if (!(fd = fopen(file, "r")))
        err(1, "Failed to open the whitelist %s", file);

    // Read each entry in the file and copy it into the whitelist structure
    while (1) {
        if (fgets(buf, 32, fd) == NULL) {
            if (feof(fd))
                break;
            else
                errx(1, "Error reading whitelist entry %s", file);
        }

        // Chop off the newline
        buf[strlen(buf) - 1] = '\0';

        // Allocate space in the list for the next entry
        whitelist.list = 
            realloc(whitelist.list, sizeof(char*) * (whitelist.numEntries + 1));
        if (!whitelist.list) err(1, "Out of memory");

        // Allocate the space for the next entry
        whitelist.list[whitelist.numEntries] = 
            malloc(sizeof(char) * (strlen(buf) + 1));
        if (!whitelist.list[whitelist.numEntries]) err(1, "Out of memory");

        strncpy(whitelist.list[whitelist.numEntries++], buf, strlen(buf) + 1);
    }
}

/**
 * Creates a url that will report the failure for the given host and then
 * returns the response from that url.
 *
 * @param   ip      IP of the host to report
 * @param   service Name of the service the host attempted to brute force
 * @return  char*   xml response from the url
 */
char *reportFailureToWeb(char *ip, char *service) {
    char url[BUFSIZ];

    snprintf(url, BUFSIZ, 
        "http://%s/"
        "?key=%s&cmd=report&reported_ip=%s&service=%s", 
        centralServer, key, ip, service);

    return getWebResponse(url);
}

/**
 * Parses the xml response from the url and then writes the results to the log
 * file.
 */
void parseXMLWebResponse(char *xml, char *host) {
    xmlDocPtr doc;
    xmlNodePtr node;
    char buf[BUFSIZ];

    doc = xmlParseMemory(xml, strlen(xml));
    if (!doc) {
        fprintf(stderr, "XML failed to parse\n");
        return;
    }

    node = xmlDocGetRootElement(doc);
    if (!node) goto parseError;

    if (xmlStrcmp(node->name, (const xmlChar *)"rsp")) 
        goto parseError;

    node = node->children;
    if (!node) goto parseError;

    snprintf(buf, BUFSIZ, "Reporting host %s -", host);
    logXMLMessage(node, buf);

    xmlFreeDoc(doc); 

    return;

parseError:
    fprintf(stderr, "Error parsing XML: %s\n", xml);
    xmlFreeDoc(doc);
}

/**
 * Tries the match the given regular expression against the string and stores
 * the value in ()s if it does match.
 *
 * @param string    String to use the regex on
 * @param regex     Standard regular expression with a single set of ()s,
 *                  representing the value to put into the return buffer
 * @param retBuf    Where to store the value matched inside the ()s
 * @param retBufSize    Size of retBuf
 * @return  int     1 when the regex matches, 0 if it does not
 */
int match(char *string, regex_t *regex, char *retBuf, int retBufSize) {
    regmatch_t matches[2];
    int ret;

    bzero(matches, sizeof(regmatch_t) * 2);

    ret = regexec(regex, string, (size_t)2, matches, 0);

    if (ret == 0) {
        if ((matches[1].rm_eo - matches[1].rm_so + 1) > retBufSize)
            return 0;
        
        // Copy the matched atom
        strncpy(retBuf, &string[matches[1].rm_so], 
            matches[1].rm_eo - matches[1].rm_so);
        retBuf[matches[1].rm_eo - matches[1].rm_so] = '\0';

        return 1;
    }

    return 0;
}

/**
 * An entry is added to the database for the given host. 
 * If the number of matched messages logged in the database for that host 
 * exceeds maxAttempts, that host is not in the whitelist, and the host is not 
 * already in the blocked table, then a rule is added to the firewall to drop 
 * all packets from the given host and the host is reported to the web server. 
 * The response from the web server is then logged.
 */
void handleAuthFailure(char *host, int maxAttempts, char *service) {
    struct in_addr ip;
    char ipbuf[32];
    struct hostent *hent;
    char *xml;

    DBG("Handling failure for '%s'\n", host);

    // Check to see if this is actually an IP and if it is
    // then just use it, otherwise we need to resolve the hostname 
    if (!inet_aton(host, &ip)) {
        hent = gethostbyname(host);

        if (hent == NULL) {
            DBG("gethostbyname failed for host: %s\n", host);
            return;
        }
        else {
            // Extract the ip if we got one back. Copy the result into a 
            // local buffer to avoid having the ip blown away if someone 
            // else calls inet_ntoa
            if (hent->h_addr_list[0] && hent->h_addrtype == AF_INET) {
                memcpy(&ip, hent->h_addr_list[0], sizeof(ip));
                host = inet_ntoa(ip);
                if (host == (char*)-1) {
                    warnx("inet_ntoa failed\n");
                    return;
                }
                snprintf(ipbuf, 32, "%s", host);
                host = ipbuf;
            }
            else {
                DBG("Failed to resolve host: %s\n", host);
                return;
            }
        }
    }

    DBG("host='%s'\n", host); 

    if (!inWhiteList(host)) {
        DBG("Logging failure attempt\n");
        logAuthFailure(host, service);

        // Report the host if they have exceeded the max number of fail attempts
        if (getHostLoginAttempts(host, service) > maxAttempts) {
            DBG("Host exceeded max attempts: %s\n", host);
            if (!hostAlreadyBlocked(host)) {
                DBG("Blocking host\n");
                blockHost(host);
                logBlocked(host);
	    		sendAlertEmail(host);

                xml = reportFailureToWeb(host, service);
                if (xml) {
                    parseXMLWebResponse(xml, host);
                }
                else {
                    DBG("Not logging failed authentication to log file\n");
                }
            }
            else {
                DBG("Already blocked host\n");
            }
        }
    }
}

/**
 * Processes the given log entry and if none of the log regexs match, 
 * nothing is done. If the entry matches, the authentication failure is then
 * handled for the host in the entry.
 *
 * @param   entry   Log entry
 * @param   log     Log information for log that entry came from
 */
void processLogEntry(char *entry, struct logType *log) {
    char host[BUFSIZ];
    struct regexList *curRegex;

    DBG("Processing log entry: %s\n", entry);

    // Try and match agains all regexs for the given log type
    for (curRegex = log->failedPatterns; curRegex; curRegex = curRegex->next) {
        bzero(host, sizeof(char) * BUFSIZ);
        if (match(entry, &curRegex->regex, host, BUFSIZ)) {
            DBG("Matched host %s for pattern %s\n", host, 
                curRegex->regexString);

            handleAuthFailure(host, curRegex->maxAttempts, curRegex->service);
            break;
        }
    }
}

/**
 * Archives the current log file and starts over. Also deletes any log files
 * older than 3 months.
 */
void rotateLogs() {
    char cmd[BUFSIZ];
    FILE *fd;
    time_t curTime;
    struct tm *structTime;
    char curDate[16];

    DBG("Rotating logs\n");

    if ((curTime = time(NULL)) == -1)
        errx(1, "Failed to get current time\n");
    if ((structTime = localtime(&curTime)) == NULL)
        errx(1, "Failed convert time to struct\n");
    if (strftime(curDate, 16, "%Y%m%d", structTime) == 0)
        errx(1, "Failed to get date string from time\n");


    // archive the current log file by appending the date to it
    snprintf(cmd, BUFSIZ, "mv %s %s-%s", LOG_FILE, LOG_FILE, curDate);
    if (system(cmd) == -1)
        err(1, "Failed to run cmd %s:", cmd);

    // re-create the log file
    if ((fd = fopen(LOG_FILE, "w")) == NULL)
        err(1, "Failed to open log: %s", LOG_FILE);
    fclose(fd);

    // remove log files older than 3 months (~= 24 * 31 * 3 = 2232 hours)
    snprintf(
        cmd, BUFSIZ, "find %s* -mtime +2232 -type f -exec rm '{}' \\;", LOG_FILE
    );
    if (system(cmd) == -1)
        err(1, "Failed to run cmd %s:", cmd);
}

/**
 * Starts a new process to sync with the server.
 */
void launchSyncWithServer() {
    int pid;

    DBG("Syncing with server\n");

    pid = fork();

    if (pid == -1) {
        err(1, "Failed to fork in order to sync with server");
    }
    else if (pid == 0) {
        syncWithServer(); 
        exit(0);
    }

    DBG("Sync process pid: %i\n", pid);
}

/**
 * Looks for a rotated version of the given file, seeks to the given point, and
 * then processes the remaining entries. The old log either has a .1, or .1.gz
 * appended to it. The log file must have been created in the last
 * 5 minutes, or else we will assume that its an old log file.
 *
 * @return int  0 upon success, 1 on failure
 */
int finishReadingRotatedLog(struct logType *log, int seekPoint) {
    char oldLog[BUFSIZ];
    char buffer[BUFSIZ];
    char cmd[BUFSIZ];
    struct stat fileStats;
    FILE *fd;

    // Look for a rotated log entry with a .1 on it
    snprintf(oldLog, BUFSIZ, "%s.1", log->name);
    if (stat(oldLog, &fileStats) == 0) {
        if (fileStats.st_ctime < (time(NULL) - 300)) {
            DBG("Old log file %s is too old\n", oldLog);
            return 1;
        }

        DBG("Reading from rotated log %s\n", oldLog);

        if ((fd = fopen(oldLog, "r")) == NULL) {
            warn("Failed to open the log %s", oldLog);
            return 1;
        }

        if (fseek(fd, seekPoint, SEEK_SET) == -1) {
            warn("Failed to seek in file %s", oldLog);
            return 1;
        }

        while (fgets(buffer, sizeof(buffer), fd) != NULL)
            processLogEntry(buffer, log);

        fclose(fd);

        return 0;
    }

    // Look for a zipped version of the rotate log
    strncat(oldLog, ".gz", BUFSIZ);
    if (stat(oldLog, &fileStats) == 0) {
        if (fileStats.st_ctime < (time(NULL) - 300)) {
            DBG("Old log file %s is too old\n", oldLog);
            return 1;
        }

        snprintf(cmd, BUFSIZ, "zcat %s | tail -c +%i", oldLog, seekPoint);

        DBG("Reading from rotated log %s\n", oldLog);

        if ((fd = popen(cmd, "r")) == NULL) {
            warn("Failed to read from old log file: %s", cmd); 
            return 1;
        }

        while (fgets(buffer, sizeof(buffer), fd) != NULL)
            processLogEntry(buffer, log);

        pclose(fd);

        return 0;
    }

    DBG("Could not find rotated log");
    return 1;
}

/**
 * Returns the size of a file in bytes.
 */
size_t filesize(const char *filename) {
    struct stat sb;

    if (stat(filename, &sb))
        err(1, "Failed to get the size of file %s", filename);

    return sb.st_size;
}

/**
 * Reads the given file and processes each entry. When the end of the file is
 * reached the size of the file is checked on a regular basis. Any new entries
 * are processed if the size of the file ever grows.
 */
void tailf() {
    char buffer[BUFSIZ];
    size_t nsize;
    FILE *str;
    uint64_t syncTime = 0;      // Time from last sync to the server
    uint64_t maintTime = 0;     // Time from last db clean
    uint64_t logRotateTime = 0; // Time from last log rotation
    struct logType *log;
    
    DBG("Tailing log files\n");

    // Initialize the size read of the log files to be their current size
    for (log = logs; log; log = log->next)
        log->osize = filesize(log->name);

    // Every time interval check the size of the file, if its bigger then it
    // was the last time we read it then read in everything since the last read
    while (1) {
        for (log = logs; log; log = log->next) {
            nsize = filesize(log->name);

            if (nsize != log->osize) {
                // If the file is smaller then it must have been rotated, try 
                // and read the rest of the contents from the old file
                if (nsize < log->osize) {
                    finishReadingRotatedLog(log, log->osize);
                    log->osize = 0;
                }

                if (!(str = fopen(log->name, "r")))
                    err(1, "Cannot open \"%s\" for read", log->name);

                fseek(str, log->osize, SEEK_SET);

                while (fgets(buffer, sizeof(buffer), str) != NULL)
                    processLogEntry(buffer, log);

                    fclose(str);
                log->osize = nsize;
            }
        }

        usleep(SLEEP_INTERVAL);

        syncTime += (uint64_t)SLEEP_INTERVAL;
        maintTime += (uint64_t)SLEEP_INTERVAL;
        logRotateTime += (uint64_t)SLEEP_INTERVAL;

        // If we have reached the interval when we should sync to the server
        // then do so. syncInteravl is in minutes 
        if (syncInterval 
            && ((syncTime / 1000 / 1000 / 60) >= syncInterval)) {
            syncTime = 0;
            launchSyncWithServer();
        }

        // Perform cleanup routines on schedule. maintInterval is in days
        if (maintInterval && 
            ((maintTime / 1000 / 1000 / 60 / 60 / 24) >= maintInterval)) {
            maintTime = 0;
            cleanDB();
        } 

        // Rotate the logs on schedule. logRotateInterval is in days
        if (logRotateInterval && ((logRotateTime / 1000 / 1000 / 60 / 60 / 24) 
                >= logRotateInterval)) {
            logRotateTime = 0;
            rotateLogs();
        }
    }
}

/**
 * Performs all operations necessary to shutdown the program.
 */
void cleanupProgram() {
    closeDBConnection();
    stopWebQuerier();
    if (pidFileCreated)
        unlink("/var/run/brutelock.pid");
}

/**
 * Signal handler for signals that should kill the program.
 */
void dieHandler(int signal) {
    cleanupProgram();
    exit(0);
}

/**
 * Get the return code from a dead child. Mostly just avoids the creation
 * of zombies.
 */
void childDieHandler(int signal) {
    int status = 0;
    if (waitpid(-1, &status, WNOHANG)) {
        if (!WIFEXITED(status))
            warnx("Child terminated with status %i", WEXITSTATUS(status));
    }
}

/**
 * Sets up the child signal handler
 */
void setupChildSignalHandler() {
    struct sigaction action;

    bzero(&action, sizeof(struct sigaction));

    if (sigaction (SIGCHLD, NULL, &action) == -1)
        err(1, "Failed to get child signal handler\n");

    action.sa_handler = childDieHandler;

    if (sigaction (SIGCHLD, &action, NULL) == -1)
        err(1, "Failed to set child signal handler\n");
}

/**
 * Prints the options for the program
 */
void printUsage() {
    printf("Usage: brutelockd [-fhsV]\n");
    printf("    -f    Run program in the foreground\n");
    printf("    -h    Print this usage\n");
    printf("    -V    Print program version\n");
}

/**
 * Checks for the pid file and exits if it already exists. Otherwise the pid
 * file is written.
 */
void createPidFile() {
    struct stat statStruct;
    FILE *pidFile;
    char pid[16];

    DBG("Creating pid file\n");

    // Check for an existing file
    if (stat("/var/run/brutelock.pid", &statStruct) == 0)
        errx(1, "The pid file /var/run/brutelock.pid already exists.\n"
            "Is brutelock already running?");

    // Write this processes pid to a file
    pidFile = fopen("/var/run/brutelock.pid", "w"); 
    if (pidFile == NULL)
        err(1, "Failed to open /var/run/brutelock.pid");
    snprintf(pid, 16, "%i", getpid());
    fwrite(&pid, strnlen(pid, 16), 1, pidFile);
    fclose(pidFile);

    pidFileCreated = 1;
}

/**
 * Main program entry point. Continually listens to log files for any entry
 * that matches a regex given for that file. Whenever an entry is found, the 
 * host is recorded, and the host is reported after a certain threshold. 
 */
int main(int argc, char **argv) {
    int daemonize = 1;
    int pid;
    int opt;

    signal(SIGINT, dieHandler);
    signal(SIGTERM, dieHandler);

    // Parse command line arguments
    while ((opt = getopt(argc, argv, "fhV")) != -1) {
        switch (opt) {
            case 'f': // Run in foreground
                daemonize = 0;
                break;

            case 'h': // Help
                printUsage();
                exit(0);
                break;

            case 'V': // Version
                printf("Version %s\n", PACKAGE_VERSION);
                exit(0);
                break;

            case '?': // Unknown parameter
                if ( isprint(optopt) )
                    warnx("Invalid option: %c\n", optopt);
                else
                    warnx("Invalid option: 0x%x", optopt);

            default:
                printUsage();
                exit(1);
        }
    }

    parseConfFile();
    loadWhitelist(WHITELIST);

    initWebQuerier();
    openDBConnection(DATABASE);

    // Make sure to handle child signals so that we dont get zombies
    setupChildSignalHandler();

    // Daemonize the program if the -f flag was not given
    if (daemonize) {
        pid = fork();
        if (pid == -1) err(1, "Fork failed");
        else if (pid > 0) exit(0);
    }

    createPidFile();
    checkFirewall();

    // This function should never return
    tailf();

    cleanupProgram();

    return 0;
}
