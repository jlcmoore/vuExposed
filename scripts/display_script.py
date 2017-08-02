#!/usr/bin/env python

# Copyright Jared Moore 2017

import subprocess
import logging
import logging.handlers
import sys
from pyrepl import Mozrepl, DEFAULT_PORT
import time
import threading
import Queue
import sqlite3
import datetime
import argparse
import os
import signal

DEFAULT_PAGE = "https://jlcmoore.github.io/vuExposed"
DISPLAY_SLEEP = 3
INIT_SLEEP = 5
LOG_FILENAME = "listen.log"
LOG_LEVEL = logging.INFO  # Could be e.g. "DEBUG" or "WARNING"
SQL_DATABASE = "/var/db/filetosql.sqlite"

TABLE_NAME = "requests"
NUM_DISPLAYS = 3
QUERY_NO_END = "select ts, source, url, user_agent from " + TABLE_NAME + " WHERE ts > ?"
QUERY = QUERY_NO_END + ";"
TIME_FORMAT = "%Y/%m/%d %H:%M:%S"

TEST_SQL_DATABASE = "test.sqlite"
TEST_MODE = True
TEST_TIME_START = "2017/08/01 15:48:01"
TEST_DISPLAY_SLEEP = DISPLAY_SLEEP
TEST_QUERY = QUERY_NO_END + " and ts < ?;"
TEST_TABLE_NAME = "requests"

def main(num_displays, num_firefox):    
    logger.info('Started')
    killer = GracefulKiller()    
    start(num_displays, num_firefox, killer)
    logger.info('Finished')

def create_logger(log_name):
    if os.path.isfile(log_name):
        os.remove(log_name)
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
    # sys.stdout = MyLogger(logger, logging.INFO)
    # Replace stderr with logging to file at ERROR level
    # sys.stderr = MyLogger(logger, logging.ERROR)
    return logger

def get_init_time():
    time = datetime.datetime.now().strftime(TIME_FORMAT)
    if TEST_MODE:
        time = TEST_TIME_START
    return time

def start(num_displays, num_firefox, killer):
    dead = threading.Event()
    firefox_procs = []
    threads = []
    try:
        last_time = get_init_time()

        logger.info("Connecting to sqlite database")
        database = SQL_DATABASE
        if TEST_MODE:
            database = TEST_SQL_DATABASE
        conn = sqlite3.connect(database)
        with conn:
            conn.row_factory = sqlite3.Row
            c = conn.cursor()
            # start firefox instances
            logger.info("Starting up firefox instances")

            firefox_to_queue = dict()
            display_num = 0
            for i in range(num_firefox):
                firefox_procs.append(subprocess.Popen(["firefox","-no-remote","-P", ("display_%d" % i),
                                                       ("--display=:%d" % display_num)],
                                                      preexec_fn=os.setsid, stdout=subprocess.PIPE))
                firefox_to_queue[i] = Queue.Queue()
                display_num += (num_displays % num_firefox) - 1
            # let firefox start
            time.sleep(INIT_SLEEP)
            ## spawn a thread for each display and start the repl there
            for i in range(num_firefox):
                t = threading.Thread(target=display_main, args=(i, firefox_to_queue[i], dead))
                t.start()
                threads.append(t)

            while not killer.kill_now:
                last_time = requests_to_queues(last_time, num_firefox, firefox_to_queue, c)
                time.sleep(sleep_time())
                # how do we delete things from the sqlite database?
    finally:
        dead.set()
        logger.info("Terminated main loop")
        for thread in threads:
            thread.join()
        logger.info("Finished waiting for threads")        
        for firefox in firefox_procs:
            os.killpg(os.getpgid(firefox.pid), signal.SIGTERM)
        logger.info("Threads finished")

def query_for_requests(last_time, new_last_time, c):
    if TEST_MODE:
        c.execute(TEST_QUERY, (last_time, new_last_time,))
    else:
        c.execute(QUERY, (last_time,))
    rows = c.fetchall()
    return rows

def requests_to_queues(last_time, num_firefox, firefox_to_queue, c):
    print last_time

    new_last_time = last_time
    if TEST_MODE:
        last_time_dt = datetime.datetime.strptime(last_time, TIME_FORMAT)
        delta = datetime.timedelta(seconds=(DISPLAY_SLEEP + 2))
        up_to_time = last_time_dt + delta
        new_last_time = up_to_time.strftime(TIME_FORMAT)

    rows = query_for_requests(last_time, new_last_time, c)
    last_time = new_last_time
    print rows
    # create intermediate lists for each display
    inter_lists = dict()
    for i in range(num_firefox):
        inter_lists[i] = []

    # populate lists
    for request in rows:
        if request['ts'] > last_time:
            last_time = request['ts']
        to_firefox = hash(ip_to_subnet(request['source'])) % num_firefox
        print to_firefox
        inter_lists[to_firefox].append(request)

    # send lists
    for i in range(num_firefox):
        # todo: think about blocking implications
        firefox_to_queue[i].put(inter_lists[i])
    
    return last_time

def ip_to_subnet(ip):
    return ip.split(".")[3]

def sleep_time():
    if TEST_MODE:
        return TEST_DISPLAY_SLEEP
    else:
        return DISPLAY_SLEEP

# thread main
def display_main(firefox_num, queue, dead):
    #start repl
    logger.info("Thread %d starting", firefox_num)
    port = DEFAULT_PORT + firefox_num

    # todo: mozrepl not starting properly, investigate
    with Mozrepl(port=port) as mozrepl:
        logger.info(mozrepl.js("repl.whereAmI()"))
        current_entry = None
        while not dead.is_set():
            try:
                # get all the new entries in the queue
                requests = queue.get(True, sleep_time()) # blocking call
                current_entry = find_best_entry(requests, current_entry)

                # todocheck document.readyState?
            except Queue.Empty:
                current_entry = None
                
            if current_entry:
                url = current_entry['url']
                user_agent = current_entry['user_agent']
            else:
                url = DEFAULT_PAGE
                user_agent = ""

            logger.info("Thread %d changing url to %s", firefox_num, url)
            change_url(mozrepl, url)
            add_user_agent(mozrepl, user_agent)
    logger.info("Thread %d ending", firefox_num)

def find_best_entry(requests, old):
    # sort based on time so most recent is first
    sorted(requests, key= lambda request: request['ts'], reverse=True)
    
    # current entry = most recent entry where entry.uid
    # == current entry.uid || most recent entry || DEFAULT_PAGE                
    for request in requests:
        if (old and request['source'] == old['source'] and
            request['url'] != old['url']):
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

### from https://stackoverflow.com/questions/18499497/how-to-process-sigterm-signal-gracefully
class GracefulKiller:
    kill_now = False
    def __init__(self):
        signal.signal(signal.SIGINT, self.exit_gracefully)
        signal.signal(signal.SIGTERM, self.exit_gracefully)
        
    def exit_gracefully(self,signum, frame):
        self.kill_now = True
###

if __name__ == "__main__":
    # Define and parse command line arguments
    parser = argparse.ArgumentParser(description="vuExposed listening service")
    parser.add_argument("-l", "--log",
                        help="file to write log to (default '" + LOG_FILENAME + "')")
    parser.add_argument("-d", "--display_num", type=int, help="the number of displays")
    parser.add_argument("-f", "--firefox_num", type=int, help="the number of firefox instances")
    # If the log file is specified on the command line then override the default
    args = parser.parse_args()
    log_name = LOG_FILENAME
    if args.log:
        log_name = args.log
    num_displays = NUM_DISPLAYS
    if args.display_num:
        num_displays = args.display_num
    if args.firefox_num:
        num_firefox = args.firefox_num

    logger = create_logger(log_name)
    main(num_displays, num_firefox)
