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
import re
import signal

DEFAULT_PAGE = "https://jlcmoore.github.io/vuExposed"
DISPLAY_SLEEP = 15
INIT_SLEEP = 5
LOG_FILENAME = "listen.log"
LOG_LEVEL = logging.DEBUG  # Could be e.g. "DEBUG" or "WARNING"
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

def main(num_displays, num_firefox, monitor):    
    logger.info('Started')
    killer = GracefulKiller()    
    start(num_displays, num_firefox, monitor_list, killer)
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

class MonitorInfo(object):
    def __init__(self,w,h,x,y):
        self.width = w
        self.height = h
        self.x_offset = x
        self.y_offset = y

def get_monitor_info():
    monitor_list = []
    line_pattern = r"^\w+-\d\Wconnected"
    geometry_pattern = r"\d+x\d+\+\d+\+\d+"
    r_line = re.compile(line_pattern)
    r_geo = re.compile(geometry_pattern)
    xrandr_out = subprocess.check_output(['xrandr','-q']).split('\n')
    monitors = filter(r_line.match, xrandr_out)
    for line in monitors:
        geometry = r_geo.findall(line)[0]
        whxy = re.split(r"[+x]",geometry)
        monitor = MonitorInfo(*whxy)
        monitor_list.append(monitor)
        logger.info("monitor at w %s h %s x %s y %s" % (whxy[0],whxy[1],whxy[2],whxy[3]))
    return monitor_list

def move_browsers(monitor_list, firefox_procs):
    firefox_counter = 0
    for m in monitor_list:
        # already distributed all browsers?
        # 'g,x,y,w,h'
        # the hack here to 10 10 allows the windows to resize to the monitor
        # in which they are placed
        geometry = "0,%s,%s,%s,%s" % (m.x_offset,m.y_offset,10,10)
        logger.info("firefox geometry " + geometry)
        pid = firefox_procs[firefox_counter].pid
        window_id = get_window_id(pid)
        firefox_counter = firefox_counter + 1
        subprocess.Popen(['wmctrl', '-ir', window_id,'-e', geometry])

def get_window_id(pid):
    window_info = subprocess.check_output(['wmctrl','-lp']).split('\n')
    for window in window_info:
        cols = re.split('\W+', window)
        if len(cols) > 2 and cols[2] == str(pid):
            return cols[0]
    return None

def start(num_displays, num_firefox, monitor_list, killer):
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
            for i in range(num_firefox):
                firefox_procs.append(subprocess.Popen(["firefox","-no-remote","-P", ("display_%d" % i)],
                                                      preexec_fn=os.setsid, stdout=subprocess.PIPE))
                firefox_to_queue[i] = Queue.Queue()
            # let firefox start
            time.sleep(INIT_SLEEP)
            move_browsers(monitor_list, firefox_procs)
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
    logger.debug("last time %s" % last_time)

    new_last_time = last_time
    if TEST_MODE:
        last_time_dt = datetime.datetime.strptime(last_time, TIME_FORMAT)
        delta = datetime.timedelta(seconds=(DISPLAY_SLEEP + 2))
        up_to_time = last_time_dt + delta
        new_last_time = up_to_time.strftime(TIME_FORMAT)

    rows = query_for_requests(last_time, new_last_time, c)
    last_time = new_last_time
    # create intermediate lists for each display
    inter_lists = dict()
    for i in range(num_firefox):
        inter_lists[i] = []

    # populate lists
    for request in rows:
        if request['ts'] > last_time:
            last_time = request['ts']
        to_firefox = hash(ip_to_subnet(request['source'])) % num_firefox
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
    logger.info("Thread %d starting", firefox_num)
    port = DEFAULT_PORT + firefox_num
    with Mozrepl(port=port) as mozrepl:
        logger.info(mozrepl.js("repl.whereAmI()"))
        current_entry = None
        change_url(mozrepl, DEFAULT_PAGE)
        while not dead.is_set():
            new_entry = None
            try:
                # get all the new entries in the queue
                requests = queue.get(True, sleep_time()) # blocking call
                print "thread %d requests %s" % (firefox_num, requests)
                print requests
                new_entry = find_best_entry(requests, current_entry)
                print "thread %d choose %s" % (firefox_num, new_entry)
                # todocheck document.readyState?
            except Queue.Empty:
                logger.debug("thread %d queue empty" % firefox_num)
                current_entry = None
                
            if not (new_entry == None and current_entry == None):
                if new_entry:
                    url = new_entry['url']
                    user_agent = new_entry['user_agent']
                else:
                    url = DEFAULT_PAGE
                    user_agent = ""

                logger.info("Thread %d changing url to %s", firefox_num, url)
                change_url(mozrepl, url)
                # TODO: this is a hack we want to check that the page is loaded
                # instead
                time.sleep(1)
                add_user_agent(mozrepl, user_agent)
                current_entry = new_entry

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
    mozrepl.js("div = document.createElement('div')")
    mozrepl.js("h1 = document.createElement('h1')")
    mozrepl.js("h1.innerHTML = '%s'" % user_agent)
    mozrepl.js("div.appendChild(h1)")
    mozrepl.js("div.style.color = 'black'")
    mozrepl.js("div.style.backgroundColor = 'white'")
    mozrepl.js("div.style.fontSize = '40px'")
    mozrepl.js("div.style.zIndex = '99999999'")
    mozrepl.js("div.style.float = 'left'")
    mozrepl.js("div.style.position = 'absolute'")
    mozrepl.js("body.insertBefore(div, body.firstChild)")

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

    logger = create_logger(log_name)
    monitor_list = get_monitor_info()

    if args.log:
        log_name = args.log

    if args.display_num:
        num_displays = args.display_num
    else:
        num_displays = len(monitor_list)

    if args.firefox_num:
        num_firefox = args.firefox_num
    else:
        num_firefox = num_displays

    if num_firefox > num_displays or num_displays > len(monitor_list):
        sys.exit()

    main(num_displays, num_firefox, monitor_list)
