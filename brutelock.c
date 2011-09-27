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

#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <stdarg.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <ctype.h>

#include <curl/curl.h>
#include <libxml/xmlmemory.h>
#include <libxml/parser.h>

#include "brutelock.h"
#include "db.h"

#define UPDATE_SERVER   "report.brutelock.com"
#define TEST_SERVER     "sandbox.brutelock.com"

// Global configuration variables
char key[BUFSIZ];
int firewall; 
char chainName[BUFSIZ];
int syncInterval;
int maintInterval;
int logRotateInterval;
char centralServer[BUFSIZ];
char alertEmail[BUFSIZ];
struct logType *logs;

void sendEmail(char *subject, char *body);

struct memBuf {
    char *buf;
    int size;
};

char curlErrBuf[CURL_ERROR_SIZE];

struct memBuf curlBuf;      // Stores the web response from a url
CURL *curl;                 // Main curl handle

#ifdef DEBUG
void DBG(char *fmt, ... ) {
    va_list args;

    va_start(args, fmt);
    vfprintf(stderr, fmt, args);
    va_end(args);
}
#endif

/**
 * Makes sure the firewall used is setup properly
 */
void checkFirewall() {
    FILE *output;
    char cmd[256];
    char buf[256];

    bzero(buf, sizeof(char) * 256);

    DBG("Checking if firewall is ready\n");

    switch (firewall) {
        case IPTABLES:
            // Make sure the brutelock chain exists
            snprintf(cmd, 256, "/sbin/iptables -nL %s 2>&1", chainName);

            if ((output = popen(cmd, "r")) == NULL)
                err(1, "Failed to run command: %s\n", cmd);


            if (fgets(buf, 256, output) == NULL)
                errx(1, "Failed to read output from iptables: %s", cmd);

            if (strstr(buf, "No chain") != NULL) {
                errx(1, "You need to create the iptables chain %s",
                    chainName);
            }

            pclose(output);

            break;

        default:
            errx(1, "Invalid firewall type: %i\n", firewall);
    }
}

/**
 * Send an email alerting that the given host has been blocked.
 */
void sendAlertEmail(char *ip) {
    char body[2048];
	char subject[512];
    int i;
    
    DBG("Sending alert email\n");

    // Make darn sure we got an IP so that we don't pass through a crazy
    // domain name and get ourselves hacked
    for (i = 0; i < strnlen(ip, 256); i++ ) {
        if (!isdigit(ip[i]) && ip[i] != '.')    
            errx(1, "Didn't get an ip where one expected in sendAlertEmail");
    }

	snprintf(subject, 512, "Blocked %s", ip);
    snprintf(body, 2048,
		"The following ip has been blocked by brutelock: %s", ip);

	sendEmail(subject, body);
}

/**
 * Sends an alert email detailing that all the given ips have been blocked.
 */
void sendSyncSummaryEmail(char **ips, int numIPs) {
	char *body;
	int length;
	char *subject;
	int bodySize;
	int i;

	DBG("Sending summary email\n");

	length = (numIPs * 16 + 512);
	body = malloc(sizeof(char *) * length);

	subject = "Blocked ips from brutelock server";
	snprintf(body, length,
		"The following ips have been marked by the brutelock server and are being blocked:\n");

	for (i = 0; i < numIPs; i++) {
		strncat(body, ips[i], length);	
		strncat(body, "\n", length);
	}	

	sendEmail(subject, body);

	free(body);
}

/**
 * Sends an email via sendmail with the given body and subject. Only sends
 * it if alertEmail is set.
 */
void sendEmail(char *subject, char *body) {
	char *cmd;
	int length;
	int status;

	length = strnlen(subject, 256) + strnlen(body, 10000) + 512;
	cmd = malloc(sizeof(char *) * length);

	// Don't send an email if no recipient given
	if (strncmp(alertEmail, "", 2) == 0)
		return;	

    snprintf(cmd, length, 
		"echo \"From: Brutelock\nTo: %s\nSubject: %s\n\n%s\n\" | /usr/sbin/sendmail %s",
		alertEmail, subject, body, alertEmail);

    if ((status = system(cmd)) == -1)
        warn(1, "Failed to send mail: %s", cmd);
    else if (WEXITSTATUS(status) != 0)
        warnx(1, "Mail command returned error: %s", cmd);

	free(cmd);
}

/**
 * Issues a command to the firewall to drop all packets from the given ip.
 */
void blockHost(char *ip) {
    char cmd[BUFSIZ];
    int status;

    switch (firewall) {
        case IPTABLES:
            snprintf(cmd, BUFSIZ, "/sbin/iptables -A %s -s %s -j DROP", 
                chainName, ip);
            if ((status = system(cmd)) == -1)
                err(1, "Failed to run command: %s\n", cmd);
            else if (WEXITSTATUS(status) != 0)
                errx(1, "Command returned error: %s\n", cmd);
            break;

        default:
            errx(1, "Invalid firewall type: %i\n", firewall);
    }
}

/**
 * Creates an entry in the list of log entry types that we want to try and match
 * entries against.
 *
 * @param service       Name to be used when reporting to the central server
 * @param logFile       Full path of log file
 * @param hostRegex     Regular expression with a single () node that will match
 *                      and extract the host from a log entry
 * @param maxAttempts   Maximum number of failed logins before alerting
 */
void addLogType(char *service, char *logFile, 
                char *hostRegex, int maxAttempts) {
    struct logType *log;
    struct logType *logTail;
    struct regexList *regex;
    struct regexList *regexTail;
    struct stat statInfo;
    char errBuf[BUFSIZ];
    int ret;

    // Make sure they passed in everything
    if (service[0] == '\0' || logFile == '\0' || hostRegex == '\0')
        errx(1, "Must specify SERVICE, LOG, and PATTERN for each service\n");  

    DBG("Service:%s Log:%s MaxAttempts:%i Regex:%s\n", 
        service, logFile, maxAttempts, hostRegex);

    // Make sure the file exists
    if ( stat(logFile, &statInfo) != 0)       
        err(1, "Error getting info on file %s", logFile);

    // Make sure the host regex has the set of () to identify the host string
    if (strstr(hostRegex, "(") == NULL || strstr(hostRegex, ")") == NULL)
        errx(1, "Regex '%s' does not contain () to identify host string", 
            hostRegex);

    // Create an empty entry for that log
    regex = (struct regexList *)malloc(sizeof(struct regexList));
    bzero(regex, sizeof(struct regexList));
    if (regex == NULL)
        err(1, "Failed to allocate space for regex");
    
    // Copy the regex string into a buffer in the struct so that its not lost
    regex->regexString = (char *)malloc(sizeof(char) * strlen(hostRegex) + 1);
    if (regex->regexString == NULL)
        err(1, "Failed to allocate space for log regex: %s\n", hostRegex);
    strncpy(regex->regexString, hostRegex, strlen(hostRegex) + 1);

    // Compile the regex so that we don't have to each time we do a match
    ret = regcomp(&regex->regex, hostRegex, REG_EXTENDED);
    if (ret != 0) {
        regerror(ret, &regex->regex, errBuf, BUFSIZ);
        errx(1, "Failed to compile regex %s: %s", hostRegex, errBuf);
    }

    regex->maxAttempts = maxAttempts;
    regex->service = (char *)malloc(sizeof(char) * strlen(service) + 1);
    if (regex->service == NULL)
        err(1, "Failed to allocate space for log service: %s\n", service);
    strncpy(regex->service, service, strlen(service) + 1);

    // Look for an entry for this log type. If it already exists, add the
    // new regex into the list of ones to check for this file
    for (logTail = logs; logTail; logTail = logTail->next) {
        if (strncmp(logFile, logTail->name, BUFSIZ) == 0) {
            // Add the new entry to the tail of the log list
            for (regexTail = logTail->failedPatterns; regexTail->next; 
                 regexTail = regexTail->next);
            regexTail->next = regex;
            return;
        }
    }
   
    // We did not find a log entry so make a new one
    log = (struct logType *)malloc(sizeof(struct logType));
    if (log == NULL)
        err(1, "Failed to allocate space for log file type");
    bzero(log, sizeof(struct logType));
    log->failedPatterns = regex;
    log->name = (char *)malloc(sizeof(char) * strlen(logFile) + 1);
    if (log->name == NULL)
        err(1, "Failed to allocate space for log name: %s\n", logFile);
    strncpy(log->name, logFile, strlen(logFile) + 1);

    // Insert onto the end of the list
    for (logTail = logs; logTail && logTail->next; logTail = logTail->next);
    if (logTail)
        logTail->next = log;
    else
        logs = log;
}

/**
 * Trims the spaces and tabs off the right hand side of the given string.
 */
char *rightTrimWhitespace(char *str) {
    int pos;

    for (pos = strnlen(str, 512) - 1;
         (str[pos] == ' ' || str[pos] == '\t') && pos > 0; pos--) {
        str[pos] = '\0';
    }

    return str;
}

/**
 * Reads in the configuration values stored in the configuration file and 
 * stores each value in its corresponding global variables.
 */
void parseConfFile() {
    FILE *fd;
    char buf[512];
    char *param;
    char *value;

    // These variables reused for each service section
    char service[512];
    char log[512];
    int maxAttempts = 0;
    char pattern[512];
    int enableSync = 1;

    bzero(log, sizeof(char) * 512);
    bzero(pattern, sizeof(char) * 512);
    bzero(service, sizeof(char) * 512);

    strncpy(centralServer, UPDATE_SERVER, 256);
 
    DBG("Parsing conf file %s\n", CONF_FILE);

    if (!(fd = fopen(CONF_FILE, "r")))
        err(1, "Failed to open configuration file %s", CONF_FILE);
 
    while (fgets(buf, 512, fd)) {
        // Ignore comments and empty lines 
        if (buf[0] == '#' || strcmp(buf, "\n") == 0)
            continue;
        
        // Start of the next service
        if (buf[0] == '[') {
            // Record info for previous service
            if (service[0] != '\0')
                addLogType(service, log, pattern, maxAttempts);

            bzero(log, sizeof(char) * 512);
            bzero(pattern, sizeof(char) * 512);
            maxAttempts = 0;
             
            if ((value = strtok(&buf[1], "]")) == NULL)
                errx(1, "Missing terminating ']' for service");
            strncpy(service, value, 512);
        }
        else {
            // Parse the values from lines of the form "parameter=value"
            if ((param = strtok(buf, "=")) == NULL)
                errx(1, "Invalid line in configuration file: %s", buf);
            if ((value = strtok(NULL, "\n")) == NULL )
                errx(1, "Must enter a value in conf file for %s\n", param);

            DBG("Config Param: %s=%s\n", param, value);
            rightTrimWhitespace(value);

            // Store the value of the parameter in the corresponsing variable
            if (strncmp(param, "KEY", 512) == 0)
                strncpy(key, value, 512);
            else if (strncmp(param, "MAX_ATTEMPT", 512) == 0)
                maxAttempts = atoi(value);
            else if (strncmp(param, "FIREWALL", 512) == 0) {
                // Store the firewall as an integer so that we can use it in a
                // switch instead of doing string comparisons all the time
                if (strncmp(value, "iptables", 512) == 0)
                    firewall = IPTABLES;
            }
            else if (strncmp(param, "CHAIN_NAME", 512) == 0)
                strncpy(chainName, value, 512);
            else if (strncmp(param, "SYNC_INTERVAL", 512) == 0)
                syncInterval = atoi(value);
            else if (strncmp(param, "MAINT_INTERVAL", 512) == 0)
                maintInterval = atoi(value);
            else if (strncmp(param, "LOG_ROTATE_INTERVAL", 512) == 0)
                logRotateInterval = atoi(value);
            else if (strncmp(param, "LOG", 512) == 0)
                strncpy(log, value, 512);
            else if (strncmp(param, "PATTERN", 512) == 0)
                strncpy(pattern, value, 512);
            else if (strncmp(param, "ENABLE_SYNC", 512) == 0)
                enableSync = atoi(value);
            else if (strncmp(param, "EMAIL", 512) == 0) {
                if (strncmp(value, "", 2) != 0) {
                    strncpy(alertEmail, value, 512);
                }
            }
            else if (strncmp(param, "TEST_MODE", 512) == 0) {
                if (atoi(value) == 1) {
                    strncpy(centralServer, TEST_SERVER, 256); 
                }
            }
            else
                errx(1, "Invalid parameter in conf file: %s\n", param);
        }
    }

    if (enableSync == 0)
        syncInterval = 0;

    // Write info for the last service
    if (service[0] != '\0')
        addLogType(service, log, pattern, maxAttempts);

    // Make sure they provided a value for everything that is required
    if (!firewall || !strcmp(key, "") ||  !strcmp(chainName, ""))
        errx(1, "Please provide all configuration values");

    DBG("Using central server: %s\n", centralServer);

    fclose(fd);
}

/**
 * Writes the given message to the end of the log file.
 */
void logEventToLogFile(char *event) {
    FILE *fd;

    if ((fd = fopen(LOG_FILE, "a")) == NULL)
        err(1, "Failed to open log: %s", LOG_FILE);

    fprintf(fd, "%s\n", event);

    fclose(fd);
}

/**
 * Skips the node if its not an element otherwise return the node. If the next 
 * node is not an element then error out, otherwise return it.
 */
xmlNodePtr skipXMLWhiteSpace(xmlNodePtr node) {
    if (node->type != XML_ELEMENT_NODE) {
        node = node->next;
        if (!node || node->type != XML_ELEMENT_NODE)
            errx(1, "No element found in xml list\n");
    }

    return node;
}

/**
 * Extracts the code and message from the given node and then puts that
 * information into the log file.
 *
 * @param node      xmlNode list where the next element has 'code' and 'msg' 
 *                  attributes
 * @param logMsg    Prepended to the message 
 */
void logXMLMessage(xmlNodePtr node, char *logMsg) {
    xmlChar *code;
    xmlChar *msg;
    char response[BUFSIZ];
    char *date;
    time_t rawTime;

    // Skip any whitespace that may be leading up to the element with the code
    // and msg attributes
    node = skipXMLWhiteSpace(node);

    code = xmlGetProp(node, (const xmlChar *)"code");
    if (!code) errx(1, "Failed to get the 'code' element from xml response\n"); 

    msg = xmlGetProp(node, (const xmlChar *)"msg");
    if (!msg) {
        xmlFree(code);
        errx(1, "Failed to get the 'msg' element from xml response\n"); 
    }        
    
    rawTime = time(NULL);
    date = ctime(&rawTime);
    date[strlen(date) - 1] = '\0';

    snprintf(response, BUFSIZ, "%s: %s code=%s\tmsg=%s", 
        date, logMsg, code, msg);
    logEventToLogFile(response);

    xmlFree(code);
}

/**
 * Callback for curl_easy_perform. This builds up the entire response from a url
 * by concatenating the buffer passed to it each time onto the user variable
 * passed in.
 */
size_t curlCallback(void *buffer, size_t size, size_t nmemb, void *userp) {
    size_t totalSize = size * nmemb;
    struct memBuf *mem = (struct memBuf *)userp;
  
    mem->buf = realloc(mem->buf, mem->size + totalSize + 1);
    memcpy(&(mem->buf[mem->size]), buffer, totalSize);
    mem->size += totalSize;
    mem->buf[mem->size] = '\0';
    
    return totalSize;
}

/**
 * Initialises the global curl handle and curl options.
 */
void initWebQuerier() {
    int ret;

    if (curl_global_init(CURL_GLOBAL_ALL))
        errx(1, "Failed to global init libcurl");
    if (!(curl = curl_easy_init()))
        errx(1, "Failed to init libcurl");
    curl_easy_setopt(curl, CURLOPT_ERRORBUFFER, curlErrBuf);

    // Set the function that is called each time a portion of the response from
    // a url is received
    if (ret = curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, curlCallback)
        != CURLE_OK)
        errx(1, "Failed to set curl callback: %s\n", ret);

    // Sets the variable passed into the callback. curlBuf is just a place
    // to build all the portions of the response into the entire response.
    if (ret = curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)&curlBuf)
        != CURLE_OK)
        errx(1, "Failed to set curl write member: %s\n", ret);
}

/**
 * Shuts down curl. 
 */
void stopWebQuerier() {
    curl_global_cleanup();
}

/**
 * Gets the response from the url via libcurl.
 *
 * @return char*    The string returned from the url
 */
char *getWebResponse(char *url) {
    char *response;

    curl_easy_setopt(curl, CURLOPT_URL, url);

    bzero(&curlBuf, sizeof(curlBuf));

    if (curl_easy_perform(curl)) {
        warnx("Failed to talk to url: %s\nReason: %s", url, curlErrBuf);
        return NULL;
    }

    // XXX Remove any whitespace before the xml. If the server no longer does 
    // this then remove this line
    for (response = curlBuf.buf; response && isspace(response[0]); response++);

    return response;
}
