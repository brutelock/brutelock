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
#include <string.h>
#include <signal.h>

#include <libxml/xmlmemory.h>
#include <libxml/parser.h>

#include "brutelock.h"

#define LAST_UPDATE_FILE    PREFIX"/db/.last_update_ts"
#define TEMP_LATEST         "/tmp/.brutelock_latest"

/**
 * Gets the time stamp stored in LAST_UPDATE_FILE and returns it.
 */
char *checkForLastUpdate() {
    FILE *fd;
    char *date = NULL;

    fd = fopen(LAST_UPDATE_FILE, "r");
    if (!fd) return NULL;

    date = malloc(sizeof(char) * BUFSIZ); 
    if (!date) return NULL;

    fgets(date, BUFSIZ, fd);

    fclose(fd);

    return date;
}

/**
 * Truncates the given file and puts the given message into it.
 */
void storeMsgInFile(char *msg, char *file) {
    FILE *fd;

    if (!(fd = fopen(file, "w")))
        err(1, "Failed to open the file %s", file);

    fprintf(fd, "%s", msg);

    fclose(fd);
}

/**
 * Tells the fireweall to clear the rules for the chain $chainName.
 */
void flushFirewallRules() {
    char cmd[BUFSIZ];
    
    switch (firewall) {
        case IPTABLES:
            snprintf(cmd, BUFSIZ, "/sbin/iptables -F %s", chainName); 
            if (system(cmd) == -1)
                err(1, "Failed to execute the command %s\n", cmd);
            break;

        default:
            errx(1, "Invalid firewall type: %i\n", firewall);
    }
}

/**
 * If an ok code or an error message was returned then just log the response.
 * Otherwise flush the firewall rules and add rules to drop packets from each
 * of the hosts listed.
 *
 * @param xml   xml string that either contains a message or a timestamp with
 *              a list of ips.
 */
void processXMLUpdateResponse(char *xml) {
    xmlDocPtr doc;
    xmlNodePtr node; 
    xmlChar *value;
    xmlChar *date;
    int numIPs = 0;
    char logMsg[BUFSIZ];
	char **newBlocks;
	int numNewBlocks = 0;

    doc = xmlParseMemory(xml, strlen(xml));
    if (!doc) {
        fprintf(stderr, "XML failed to parse: %s\n", xml);
        return;
    }

    node = xmlDocGetRootElement(doc);
    if (!node) goto parseError;

    if (xmlStrcmp(node->name, (const xmlChar *)"rsp")) 
        goto parseError;

    value = xmlGetProp(node, (const xmlChar *)"stat");
    if (!value) goto parseError;

    node = node->children;
    if (!node) goto parseError;

    // If this is an error message than log it
    if (strcmp((char *)value, "ok") != 0) {
        DBG("Error message returned\n");
        logXMLMessage(node, "Updating -");
        xmlFree(value);
        xmlFreeDoc(doc);
        return;
    }

    node = skipXMLWhiteSpace(node);

    // If this is just a message than log it 
    if (xmlStrcmp(node->name, (const xmlChar *)"timestamp")) {
        DBG("Ok message returned\n");
        logXMLMessage(node, "Updating -");
        xmlFree(value);
        xmlFreeDoc(doc);
        return;
    }
    
    // Add each of the ips in the response list to the firewall
    storeMsgInFile(xml, TEMP_LATEST);

    // Extract the timestamp and put it into the last update time file
    date = xmlNodeListGetString(doc, node->xmlChildrenNode, 1);
    DBG("Time stamp = %s\n", date);
    storeMsgInFile((char *)date, LAST_UPDATE_FILE);

    flushFirewallRules();
	flushBlockedTable();

    // Block each of the ips listed
    node = skipXMLWhiteSpace(node);
    while (node) {
        value = xmlNodeListGetString(doc, node->xmlChildrenNode, 0);
        blockHost((char *)value); 

		// If we haven't blocked this ip already, add it to the
		// list for the summary email
        if (!hostAlreadyBlocked((char *)value)) {
			numNewBlocks++;
			newBlocks = realloc(newBlocks, sizeof(char *) * numNewBlocks);
			newBlocks[numNewBlocks - 1] = (char *)value;
        }

        numIPs++;
        node = node->next;

        // Get the next node if there is one.
        if (node->type != XML_ELEMENT_NODE && node->next == NULL) break;
        node = skipXMLWhiteSpace(node);
    }

	if (numNewBlocks > 0)
		sendSyncSummaryEmail(newBlocks, numNewBlocks);

    if (unlink(TEMP_LATEST))
        warn("Failed to remove file %s", TEMP_LATEST);

    // Record the time and number of ips processed in the log file
    snprintf(logMsg, BUFSIZ, "%s: Processed %i records", date, numIPs);
    logEventToLogFile(logMsg);

    xmlFree(value);
    xmlFree(date);
    xmlFreeDoc(doc);

    return;

parseError:
    fprintf(stderr, "Error parsing XML: %s\n", xml);
    xmlFreeDoc(doc);
}

/**
 * Gets the latest list of hosts to block from the
 * server and then tells the firewall to drop all packets from them.
 */
void syncWithServer() {
    char *lastUpdate;
    char url[BUFSIZ];
    char *xml;

    lastUpdate = checkForLastUpdate();
    DBG("Last Update = %s\n", lastUpdate);

    snprintf(url, BUFSIZ, 
        "http://update.brutelock.com/"
        "?key=%s&cmd=update", key);

    if (lastUpdate) {
        strncat(url, "&last_update=", BUFSIZ);
        strncat(url, lastUpdate, BUFSIZ);
    }

    xml = getWebResponse(url);
    if (!xml) errx(1, "Failed to get a response from the server");
    processXMLUpdateResponse(xml);

    if (lastUpdate) 
        free(lastUpdate);
}
