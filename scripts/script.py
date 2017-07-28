#!/usr/bin/env python

# Copyright Jared Moore 2017

import subprocess
import logging
import logging.handlers
import sys
from pyrepl import Mozrepl, DEFAULT_PORT
import time
import threading
from Queue import Queue
import sqlite3
import datetime
import argparse
import os
import signal

DEFAULT_PAGE = "https://jlcmoore.github.io/vuExposed"
DISPLAY_SLEEP = 3
LOG_FILENAME = "/tmp/listen.log"
LOG_LEVEL = logging.INFO  # Could be e.g. "DEBUG" or "WARNING"
SQL_DATABASE = "/var/db/filetosql.sqlite"
TABLE_NAME = "files"
NUM_DISPLAYS = 3
QUERY = "select ts, source, url, user_agent, referrer, local_name, original_name from " + TABLE_NAME + " WHERE ts > ?;"
TIME_FORMAT = "%Y/%m/%d %H:%M:%S"
TEST_MODE = True

def main(num_displays):    
    logger.info('Started')
    start(num_displays)
    logger.info('Finished')
    
def start(num_displays):
    dead = threading.Event()
    firefox_procs = []
    try:
        last_time = datetime.datetime.now().strftime(TIME_FORMAT)
        if TEST_MODE:
            last_time = datetime.datetime(1900,1,1).strftime(TIME_FORMAT)

        logger.info("Connecting to sqlite database")
        conn = sqlite3.connect(SQL_DATABASE)
        with conn:
            conn.row_factory = sqlite3.Row
            c = conn.cursor()
            # start firefox instances
            logger.info("Starting up firefox instances")

            display_to_queue = dict()
            for i in range(num_displays):
                firefox_procs.append(subprocess.Popen(["firefox","-no-remote",("-P display_%d" % i),
                                                       ("--display=:%d" % i), "&"],
                                                      preexec_fn=os.setsid, stdout=subprocess.PIPE))
                display_to_queue[i] = Queue()
            # let firefox start
            time.sleep(5)
            ## spawn a thread for each display and start the repl there
            for i in range(num_displays):
                t = threading.Thread(target=display_main, args=(i, display_to_queue[i], dead))
                t.start()

            while True:
                last_time = requests_to_queues(last_time, num_displays, display_to_queue, c)
                time.sleep(DISPLAY_SLEEP)
                # how do we delete things from the sqlite database?
            
            logger.info("Terminated main loop")
    finally:
        dead.set()
        for firefox in firefox_procs:
            os.killpg(os.getpgid(firefox.pid), signal.SIGTERM)

def requests_to_queues(last_time, num_displays, display_to_queue, c):
    print last_time
    c.execute(QUERY, (last_time,))
    rows = c.fetchall()

    # create intermediate lists for each display
    inter_lists = dict()
    for i in range(num_displays):
        inter_lists[i] = []

    # populate lists
    for request in rows:
        if request['ts'] > last_time:
            last_time = request['ts']
        to_display = hash(request['source']) % num_displays
        inter_lists[to_display].append(request)

    # send lists
    for i in range(num_displays):
        # todo: think about blocking implications
        display_to_queue[i].put(inter_lists[i])
    
    return last_time
        
# thread main
def display_main(display_num, queue, dead):
    #start repl
    logger.info("Thread %d starting", display_num)
    port = DEFAULT_PORT + display_num

    # todo: mozrepl not starting properly, investigate
    with Mozrepl(port) as mozrepl:
        logger.info(mozrepl.js("repl.whereAmI()"))
        current_entry = None
        while not dead.is_set():
            try:
                # get all the new entries in the queue
                requests = queue.get(True, DISPLAY_SLEEP) # blocking call
                current_entry = find_best_entry(requests, entry)

                # todocheck document.readyState?
            except Queue.Empty:
                current_entry = None
                
            if current_entry:
                url = current_entry['url']
                user_agent = current_entry['user_agent']
            else:
                url = DEFAULT_PAGE
                user_agent = ""

            logger.info("Thread %d changing url to %s", display_num, url)
            change_url(mozrepl, url)
            add_user_agent(mozrepl, user_agent)
    logger.info("Thread %d ending", display_num)

def find_best_entry(requests, old):
    # sort based on time so most recent is first
    sorted(requets, key= lambda request: request['ts'], reverse=True)
    
    # current entry = most recent entry where entry.uid
    # == current entry.uid || most recent entry || DEFAULT_PAGE                
    for request in requests:
        if (request['source'] == current_entry['source'] and
            request['url'] != current_entry['url']):
            return request

    if len(requests) > 0:
        return requests[0]
    else:
        return None
        
def change_url(mozrepl, url):
    mozrepl.js("content.location.href = '%s'" % url)    
    
def add_user_agent(mozrepl, user_agent):
    mozrepl.js("body = content.document.body")
    mozrepl.js("element = document.createElement('h1')")
    mozrepl.js("element.innerHTML = '%s'" % user_agent)
    mozrepl.js("body.insertBefore(element, body)")

###### SETUP
# from http://blog.scphillips.com/posts/2013/07/getting-a-python-script-to-run-in-the-background-as-a-service-on-boot/
# Make a class we can use to capture stdout and sterr in the log
# todo: only redirect when actually running for a long time
'''
class MyLogger(object):
    def __init__(self, logger, level):
        """Needs a logger and a logger level."""
        self.logger = logger
        self.level = level
        
    def write(self, message):
        # Only log if there is a message (not just a new line)
        if message.rstrip() != "":
            self.logger.log(self.level, message.rstrip())
'''
            
if __name__ == "__main__":
    # Define and parse command line arguments
    parser = argparse.ArgumentParser(description="vuExposed listening service")
    parser.add_argument("-l", "--log",
                        help="file to write log to (default '" + LOG_FILENAME + "')")
    parser.add_argument("-d", "--display_num", type=int, help="the number of displays")
    # If the log file is specified on the command line then override the default
    args = parser.parse_args()
    log_name = LOG_FILENAME
    if args.log:
        log_name = args.log
    num_displays = NUM_DISPLAYS
    if args.display_num:
        num_displays = args.display_num
        
    # Configure logging to log to a file, making a new file at midnight and
    # keeping the last 3 day's data
    # Give the logger a unique name (good practice)
    logger = logging.getLogger(__name__)
    # Set the log level to LOG_LEVEL
    logger.setLevel(LOG_LEVEL)
    # Make a handler that writes to a file, making a new file at midnight
    # and keeping 3 backups
    handler = logging.handlers.TimedRotatingFileHandler(log_name,
                                                        when="midnight",
                                                        backupCount=3)
    # Format each log message like this
    formatter = logging.Formatter('%(asctime)s %(levelname)-8s %(message)s')
    # Attach the formatter to the handler
    handler.setFormatter(formatter)
    # Attach the handler to the logger
    logger.addHandler(handler)
                
    # Replace stdout with logging to file at INFO level
#    sys.stdout = MyLogger(logger, logging.INFO)
    # Replace stderr with logging to file at ERROR level
   # sys.stderr = MyLogger(logger, logging.ERROR)
    
    main(num_displays)
