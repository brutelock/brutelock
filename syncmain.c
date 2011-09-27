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

#include <signal.h>
#include <stdlib.h>

#include <brutelocksync.h>
#include <brutelock.h>

#include "db.h"

/**
 * Performs all operations necessary to shutdown the program.
 */
void cleanupProgram() {
    stopWebQuerier();
}

/**
 * Signal handler for signals that should kill the program.
 */
void dieHandler(int signal) {
    cleanupProgram();
    exit(0);
}

/**
 * Main program entry point. Looks for blacklist updates from the server. 
 */
int main(int argc, char **argv) {
    atexit(cleanupProgram);
    signal(SIGINT, dieHandler);
    signal(SIGTERM, dieHandler);

    parseConfFile(CONF_FILE);
	openDBConnection(DATABASE);
    initWebQuerier();

    syncWithServer(); 

	closeDBConnection();

    return 0;
}
