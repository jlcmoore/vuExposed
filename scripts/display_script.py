#!/usr/bin/env python

# Copyright Jared Moore 2017
import argparse
import datetime
import logging
import logging.handlers
import os
import Queue
import re
import signal
import sqlite3
import subprocess
import sys
import threading
import time
from adblockparser import AdblockRules
from pyrepl import Mozrepl, DEFAULT_PORT
from daemon import Daemon



BLOCK_FILES = ["easylist.txt"]

DEFAULT_PAGE = "https://jlcmoore.github.io/vuExposed/monitor.html"
MACHINE_IP = '192.168.1.125'
MACHINE_PROXY_PORT = 10000


IS_PROXY = True

DISPLAY_SLEEP = 20

INIT_SLEEP = 5

LOG_FILENAME = "listen.log"
LOG_LEVEL = logging.DEBUG  # Could be e.g. "DEBUG" or "WARNING"

SQL_DATABASE = "/var/db/httptosql.sqlite"
TABLE_NAME = "http"
NUM_DISPLAYS = 3
QUERY_NO_END = "select ts, source, host, uri, user_agent,referrer, source_port, dest_port from " + TABLE_NAME + " WHERE ts > ?"
QUERY = QUERY_NO_END + ";"
DELETE_QUERY = "delete from " + TABLE_NAME + " where ts < ?;"
TIME_FORMAT = "%Y/%m/%d %H:%M:%S"

TEST_SQL_DATABASE = "test.sqlite"
TEST_MODE = False
TEST_TIME_START = "2017/08/01 15:48:01"
TEST_DISPLAY_SLEEP = DISPLAY_SLEEP
TEST_QUERY = QUERY_NO_END + " and ts < ?;"
TEST_TABLE_NAME = "requests"


class MonitorInfo(object):
    def __init__(self,w,h,x,y):
        self.width = w
        self.height = h
        self.x_offset = x
        self.y_offset = y

def get_window_id(pid):
    window_info = subprocess.check_output(['wmctrl','-lp']).split('\n')
    for window in window_info:
        cols = re.split('\W+', window)
        if len(cols) > 2 and cols[2] == str(pid):
            return cols[0]
    return None

def move_windows(monitor_list, procs):
    monitor_counter = 0
    for proc in procs:
        # already distributed all browsers?
        # 'g,x,y,w,h'
        # the hack here to 10 10 allows the windows to resize to the monitor
        # in which they are placed
        m = monitor_list[monitor_counter]
        geometry = "0,%s,%s,%s,%s" % (m.x_offset,m.y_offset,10,10)
        logger.info("firefox geometry " + geometry)
        pid = proc.pid
        window_id = get_window_id(pid)
        monitor_counter = monitor_counter + 1
        logger.info("Moving %s to %s", window_id, geometry)
        subprocess.Popen(['wmctrl', '-ir', window_id,'-e', geometry])

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

def main():    
    logger.info('Started')
    killer = GracefulKiller()
    monitor_list = get_monitor_info() 
    run(monitor_list, killer)
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
    #sys.stdout = MyLogger(logger, logging.INFO)
    # Replace stderr with logging to file at ERROR level
    #sys.stderr = MyLogger(logger, logging.ERROR)
    return logger

def get_init_time():
    time = datetime.datetime.now().strftime(TIME_FORMAT)
    if TEST_MODE:
        time = TEST_TIME_START
    return time

def get_rules():
    raw_rules = []
    for filename in BLOCK_FILES:
        raw_rules = raw_rules + open(filename).readlines()
    return AdblockRules(raw_rules,use_re2=True)

def run(monitor_list, killer):
    dead = threading.Event()
    firefox_procs = []
    threads = []
    num_displays = len(monitor_list)
    num_firefox  = len(monitor_list)
    try:
        last_time = get_init_time()
        rules = get_rules()
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
            move_windows(monitor_list, firefox_procs)
            ## spawn a thread for each display and start the repl there
            for i in range(num_firefox):
                t = threading.Thread(target=display_main, args=(i, firefox_to_queue[i], dead))
                t.start()
                threads.append(t)

            while not killer.kill_now:
                last_time = requests_to_queues(last_time, num_firefox, firefox_to_queue, c, rules)
                time.sleep(sleep_time())
                # how do we delete things from the sqlite database?
                
    finally:
        dead.set()
        logger.info("Terminated main loop")
        for firefox in firefox_procs:
            os.killpg(os.getpgid(firefox.pid), signal.SIGTERM)
        for thread in threads:
            thread.join()
        logger.info("Finished waiting for threads")        
        logger.info("Threads finished")

def query_for_requests(last_time, new_last_time, c):
    if TEST_MODE:
        c.execute(TEST_QUERY, (last_time, new_last_time,))
    else:
        c.execute(QUERY, (last_time,))
    rows = c.fetchall()

    return rows

def requests_to_queues(last_time, num_firefox, firefox_to_queue, c, rules):
    logger.debug("last time %s" % last_time)

    new_last_time = last_time
    if TEST_MODE:
        last_time_dt = datetime.datetime.strptime(last_time, TIME_FORMAT)
        delta = datetime.timedelta(seconds=(DISPLAY_SLEEP + 2))
        up_to_time = last_time_dt + delta
        new_last_time = up_to_time.strftime(TIME_FORMAT)

    logger.info("Querying for requests newer than %s" % last_time)
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
        logger.debug("Potential request for %s from src ip %s", get_url(request), request['source'])
        if request['source'] == MACHINE_IP:
            # block tracking sites, malware, etc.
            if not rules.should_block(get_url(request)):
                # TODO: just hash user agent instead so that the router doesn't
                # need to also run port-mirroring??
                to_firefox = hash(request['user_agent']) % num_firefox
                inter_lists[to_firefox].append(request)
                logger.debug("Added request for %s to browswer %d", get_url(request), to_firefox)

    # send lists
    for i in range(num_firefox):
        # todo: think about blocking implications
        firefox_to_queue[i].put(inter_lists[i])
    
    # need to delete old entries in table, but database is read only..
    # c.execute(DELETE_QUERY, (last_time,))
    return last_time

def get_url(request):
    url = request['host'] + request['uri']
    if url.startswith('wwww.'):
        url = url[1:]
    return "http://" + url

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
        current_entry = None
        change_url(mozrepl, DEFAULT_PAGE)
        logger.info(mozrepl.js("repl.whereAmI()"))
        while not dead.is_set():
            new_entry = None
            try:
                # get all the new entries in the queue
                requests = queue.get(True, sleep_time()) # blocking call
                logger.debug("thread %d requests %s", firefox_num, requests)
                print requests
                new_entry = find_best_entry(requests, current_entry)
                
                # todocheck document.readyState?
            except Queue.Empty:
                logger.debug("thread %d queue empty", firefox_num)
                current_entry = None
                
            if not (new_entry == None and current_entry == None):
                # TODO: as a backup check the mime type of the requested url
                # if bad, just wait
                if new_entry:
                    url = get_url(new_entry)
                    user_agent = new_entry['user_agent']
                    logger.debug("thread %d new entry source: %s", firefox_num, 
                        new_entry['source'])
                    print new_entry
                else:
                    url = DEFAULT_PAGE
                    user_agent = ""

                logger.info("Thread %d changing url to %s", firefox_num, url)
                change_url(mozrepl, url)
                # TODO: this is a hack we want to check that the page is loaded
                # instead
                # document.readyState === 'complete'
                # but do we really care about it that much? no...
                time.sleep(.1)
                add_user_agent(mozrepl, user_agent)
                time.sleep(2)
                add_user_agent(mozrepl, user_agent)
                current_entry = new_entry

    logger.info("Thread %d ending", firefox_num)

def find_best_entry(requests, old):
    # sort based on time so most recent is first
    
    # todo, testing with shortest url
    sorted(requests, key= lambda request: len(get_url(request)))

    #sorted(requests, key= lambda request: request['ts'], reverse=True)
    # current entry = most recent entry where entry.uid
    # == current entry.uid || most recent entry || DEFAULT_PAGE                
    #for request in requests:
    #    if (old and request['user_agent'] == old['user_agent'] and
    #        get_url(request) != get_url(old)):
    #        return request

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

### from https://stackoverflow.com/questions/18499497/how-to-process-sigterm-signal-gracefully
class GracefulKiller:
    kill_now = False
    def __init__(self):
        signal.signal(signal.SIGINT, self.exit_gracefully)
        signal.signal(signal.SIGTERM, self.exit_gracefully)
        
    def exit_gracefully(self,signum, frame):
        self.kill_now = True
###

class DisplayDaemon(Daemon):
    def run(self):
            main()

# TODO: turn into a class and don't use this logger
logger = create_logger(LOG_FILENAME)

if __name__ == "__main__":
    daemon = DisplayDaemon('/tmp/display_daemon.pid')
    if len(sys.argv) == 2:
            if 'start' == sys.argv[1]:
                    daemon.start()
            elif 'stop' == sys.argv[1]:
                    daemon.stop()
            elif 'restart' == sys.argv[1]:
                    daemon.restart()
            else:
                    print "Unknown command"
                    sys.exit(2)
            sys.exit(0)
    else:
            print "usage: %s start|stop|restart" % sys.argv[0]
            sys.exit(2)