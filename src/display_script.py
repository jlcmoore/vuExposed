#!/home/listen/.virtualenvs/display_script/bin/python python

"""
***
The vuExposed to display http requests recorded in a sqlite
database on a number of firefox instances on different monitors
***
Author: https://jlcmoore.github.io
License: ../LICENSE
"""
import argparse
import datetime
import logging
import logging.handlers
import os
import Queue
import re
import signal
import socket
import sqlite3
import ssl
import subprocess
import sys
import threading
import time
import urllib
import urllib2

from adblockparser import AdblockRules
import httpagentparser
from pyrepl import Mozrepl, DEFAULT_PORT
from daemon import Daemon

TMP_DIR = '/home/listen/Documents/vuExposed/display/'
ACCEPTABLE_HTTP_STATUSES = [200, 201]
BLOCK_FILES = ["block_lists/easylist.txt", "block_lists/unified_hosts_and_porn.txt"]
DEFAULT_PAGE = "file:///home/listen/Documents/vuExposed/docs/monitor.html"
DISPLAY_SLEEP = 5
DISPLAY_TIME_NO_NEW_REQUESTS = 120
DISPLAY_CYCLES_NO_NEW_REQUESTS = int(DISPLAY_TIME_NO_NEW_REQUESTS / DISPLAY_SLEEP)
DOCTYPE_PATTERN = re.compile(r"!doctype html", re.IGNORECASE)
FILTER_LOAD_URL_TIMEOUT = 2
HTML_MIME = "text/html"
IGNORE_USER_AGENTS = ['Python-urllib/1.17',
                      ('Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:54.0)'
                       ' Gecko/20100101 Firefox/54.0')]
INIT_SLEEP = 5
IS_PROXY = True
LOCAL_IP_PATTERN = re.compile(r"192\.168\.1\.\d{1,3}")
LOG_FILENAME = "listen.log"
LOG_LEVEL = logging.DEBUG  # Could be e.g. "DEBUG" or "WARNING
MACHINE_IP = '192.168.1.125'
MACHINE_PROXY_PORT = 10000
MAX_MONITOR_LIST_URLS = 5
NUM_DISPLAYS = 3
PID_FILE = 'display_daemon.pid'
PORT_MIRRORING = True
SQL_DATABASE = "/var/db/httptosql.sqlite"
TABLE_NAME = "http"
QUERY_NO_END = ("select ts, source, host, uri, user_agent,referrer, source_port, "
                "dest_port from " + TABLE_NAME + " WHERE ts > ?")
QUERY = QUERY_NO_END + ";"
DELETE_QUERY = "delete from " + TABLE_NAME + " where ts < ?;"
RULE_PATTERN = re.compile(r"(\d{1,3}\.){3}\d{1,3}\W([\w\-\d]+\.)+[\w\-\d]+")
WAIT_AFTER_BOOT = 30
WAIT_BETWEEN_FIREFOX_FAILS = 20

TIME_FORMAT = "%Y/%m/%d %H:%M:%S"
FILE_TIME_FORMAT = "%Y-%m-%d_%H:%M:%S"

TEST_MODE = False
TEST_DISPLAY_SLEEP = DISPLAY_SLEEP
TEST_QUERY = QUERY_NO_END + " and ts < ?;"
TEST_SQL_DATABASE = "assets/test.sqlite"
TEST_TABLE_NAME = "requests"
TEST_TIME_START = "2017/08/01 15:48:01"

class MonitorInfo(object):
    """
    A class to represent information about each monitor on a linux system
    """
    def __init__(self, w, h, x, y):
        self.width = w
        self.height = h
        self.x_offset = x
        self.y_offset = y

def get_window_id(pid):
    """
    Return the window id (using command `wmctl`) for process with pid pid
    """
    window_info = subprocess.check_output(['wmctrl', '-lp']).split('\n')
    for window in window_info:
        cols = re.split(r'\s+', window)
        if len(cols) > 2 and cols[2] == str(pid):
            return cols[0]
    return None

def move_windows(monitor_list, procs, logger):
    """
    For each process in procs, move the window handled by the process
    to a different monitor as defined in monitor_list
    """
    monitor_counter = 0
    for proc in procs:
        # 'g,x,y,w,h'
        # the hack here to 10 10 allows the windows to resize to the monitor
        # in which they are placed
        monitor = monitor_list[monitor_counter]
        geometry = "0,%s,%s,%s,%s" % (monitor.x_offset, monitor.y_offset, 10, 10)
        logger.info("firefox geometry " + geometry)
        pid = proc.pid
        window_id = get_window_id(pid)
        if not window_id:
            logger.error("Could not get window id of firefox instance; trying again")
            return False
        monitor_counter = monitor_counter + 1
        logger.info("Moving %s to %s", window_id, geometry)
        subprocess.Popen(['wmctrl', '-ir', window_id, '-e', geometry])
    return True

def get_monitor_info(logger):
    """
    Determine the current monitor configureation of the system using
    `xrandr`. Returns a list of MonitorInfo objects
    """
    monitor_list = []
    line_pattern = r"^\w+-\d\Wconnected"
    geometry_pattern = r"\d+x\d+\+\d+\+\d+"
    r_line = re.compile(line_pattern)
    r_geo = re.compile(geometry_pattern)
    xrandr_out = subprocess.check_output(['xrandr', '-q']).split('\n')
    monitors = filter(r_line.match, xrandr_out)
    for line in monitors:
        geometry = r_geo.findall(line)[0]
        whxy = re.split(r"[+x]", geometry)
        monitor = MonitorInfo(*whxy)
        monitor_list.append(monitor)
        logger.info("monitor at w %s h %s x %s y %s", *whxy)
    return monitor_list

def create_logger(log_name):
    """
    Create a logger with log_name and set it up to rotate at midnight and keep
    the last five days of data
    """
    if os.path.isfile(log_name):
        time = datetime.datetime.now().strftime(FILE_TIME_FORMAT)
        os.rename(log_name, log_name + "." + time + ".old")
    log = logging.getLogger(__name__)
    log.setLevel(LOG_LEVEL)
    handler = logging.handlers.TimedRotatingFileHandler(log_name,
                                                        when="midnight",
                                                        backupCount=3)
    formatter = logging.Formatter('%(asctime)s %(levelname)-8s %(message)s')
    handler.setFormatter(formatter)
    log.addHandler(handler)

    sys.stdout = LoggerWriter(log, logging.INFO)
    sys.stderr = LoggerWriter(log, logging.ERROR)
    return log

def get_init_time():
    """
    Get the current time, or if test mode get the test start time
    """
    init_time = datetime.datetime.now().strftime(TIME_FORMAT)
    if TEST_MODE:
        init_time = TEST_TIME_START
    return init_time

def get_rules():
    """
    Return an AdblockRules object representing the rules
    expressed in BLOCK_FILES
    """
    raw_rules = []
    for filename in BLOCK_FILES:
        file_rules = []
        with open(filename) as rule_file:
            for line in rule_file:
                if '#' not in line and re.search(RULE_PATTERN, line):
                    ipandrule = re.split(r"\s", line)
                    if len(ipandrule) > 1:
                        rule = ipandrule[1]
                        file_rules.append(rule)
        raw_rules = raw_rules + file_rules
    return AdblockRules(raw_rules, use_re2=True)

def start_display(init_sleep):
    """
    Main thread method for the display script. Spins off child
    processes for each firefox instance and sends urls to them
    from sqlite database.
    """
    logger = create_logger(TMP_DIR + LOG_FILENAME)
    dead = threading.Event()
    killer = GracefulKiller(dead)
    logger.info('Started')
    monitor_list = get_monitor_info(logger)
    firefox_procs = []
    threads = []
    num_firefox = len(monitor_list)

    time.sleep(init_sleep)
    try:
        last_time = get_init_time()
        rules = get_rules()
        
        logger.info("Starting up firefox instances")

        firefox_to_queue = dict()
        for i in range(num_firefox):
            firefox_to_queue[i] = Queue.Queue()
        
        firefox_procs = setup_browsers(num_firefox, firefox_procs, monitor_list, logger)
        logger.info("Browsers setup")
        # spawn a thread for each display
        for i in range(num_firefox):
            thread = threading.Thread(target=display_main, args=(i, firefox_to_queue[i],
                                                                 dead, logger))
            thread.start()
            threads.append(thread)

        while not dead.is_set():
            last_time = requests_to_queues(last_time, num_firefox, firefox_to_queue,
                                           rules, logger)
            time.sleep(sleep_time())
            # how do we delete things from the sqlite database?
    finally:
        dead.set()
        logger.info("Terminated main loop")
        for thread in threads:
            thread.join()
        kill_firefox(firefox_procs)
        logger.info("Finished waiting for threads")
        logger.info("Threads finished")
        logger.info('Finished')

def setup_browsers(firefox_num, firefox_procs, monitor_list, logger):
    in_position = False
    while not in_position:
        for i in range(firefox_num):
            logger.info("Trying to create firefox instances and move them")
            firefox_procs.append(subprocess.Popen(["firefox", "-no-remote", "-P",
                                                   ("display_%d" % i)],
                                                  preexec_fn=os.setsid,
                                                  stdout=subprocess.PIPE))
            # let firefox start
            time.sleep(INIT_SLEEP)
            in_position = move_windows(monitor_list, firefox_procs, logger)
            if not in_position:
                kill_firefox(firefox_procs)
                firefox_procs = []
                time.sleep(WAIT_BETWEEN_FIREFOX_FAILS)
    return firefox_procs

def kill_firefox(firefox_procs):
    for firefox in firefox_procs:
        os.killpg(os.getpgid(firefox.pid), signal.SIGTERM)

def query_for_requests(last_time, new_last_time, logger):
    """
    Return the rows from the sqlite database after last_time
    (and before new_last_time if test mode)
    """
    database = SQL_DATABASE
    if TEST_MODE:
        database = TEST_SQL_DATABASE
    conn = sqlite3.connect(database)
    rows = []
    try:
        with conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            if TEST_MODE:
                cursor.execute(TEST_QUERY, (last_time, new_last_time,))
            else:
                cursor.execute(QUERY, (last_time,))
            rows = cursor.fetchall()
    except sqlite3.Error as err:
        logger.debug("Sqlite error: %s", err)
    return rows

def get_test_last_time(last_time):
    """
    Computes a new last time, adding a delta to it
    """
    last_time_dt = datetime.datetime.strptime(last_time, TIME_FORMAT)
    delta = datetime.timedelta(seconds=(DISPLAY_SLEEP + 2))
    up_to_time = last_time_dt + delta
    new_last_time = up_to_time.strftime(TIME_FORMAT)
    return new_last_time

def requests_to_queues(last_time, num_firefox, firefox_to_queue, rules, logger):
    """
    Part of main thread.
    Queries database for new entries, filters, and sends them off to the queues
    for the firefox threads
    """
    logger.debug("last time %s", last_time)

    new_last_time = last_time
    if TEST_MODE:
        new_last_time = get_test_last_time(last_time)

    logger.info("Querying for requests newer than %s", last_time)
    rows = query_for_requests(last_time, new_last_time, logger)
    last_time = new_last_time

    # create intermediate lists for each display
    inter_lists = dict()
    for i in range(num_firefox):
        inter_lists[i] = []

    # populate lists
    for request in rows:
        if request['ts'] > last_time:
            last_time = request['ts']
        url = get_url(request)
        logger.debug("Potential request for %s", url)
        if is_wifi_request(request) and not rules.should_block(url):
            logger.debug("Valid wifi and non-blocked request for %s from src ip %s", url, request['source'])
            to_firefox = hash(request['user_agent']) % num_firefox
            if len(inter_lists[to_firefox]) < MAX_MONITOR_LIST_URLS and can_show_url(url, logger):
                inter_lists[to_firefox].append(request)
                logger.info("Added request for %s to browswer %d", url, to_firefox)

    # send lists
    for i in range(num_firefox):
        firefox_to_queue[i].put(inter_lists[i])

    # need to delete old entries in table, but database is read only..
    # c.execute(DELETE_QUERY, (last_time,))
    return last_time

def get_url(request):
    """
    For the sqlite request with 'host' and 'uri' returns url
    """
    url = request['host'] + urllib.quote(request['uri'].encode('utf-8'))
    # hack to deal with mitmf
    if url.startswith('wwww.'):
        url = url[1:]
    return "http://" + url

def can_show_url(url, logger):
    """
    Returns true if the given url is a loadable full html document
    """
    try:
        res = urllib2.urlopen(url, timeout=FILTER_LOAD_URL_TIMEOUT)
        http_message = res.info()
        full = http_message.type # 'text/plain'
        code = res.getcode()
        # make sure there was not a redirect, that it is html, and the page was accepted
        if res.geturl() == url and full == HTML_MIME and code in ACCEPTABLE_HTTP_STATUSES:
            data = res.read()
            return re.search(DOCTYPE_PATTERN, data)
    except (urllib2.HTTPError, urllib2.URLError,
            socket.timeout, socket.error, ssl.SSLError) as error:
        logger.debug('url open error for %s, error: %s', url, error)
    return False

def is_wifi_request(request):
    """
    Returns True if the sqlite object request comes from a machine
    on the wifi network
    """
    ip = request['source']
    if PORT_MIRRORING:
        result = (not re.search(MACHINE_IP, ip) and
                  not request['user_agent'] in IGNORE_USER_AGENTS)
    else:
        result = (re.search(MACHINE_IP, ip) and
                  request['source_port'] == MACHINE_PROXY_PORT)
    return result

def sleep_time():
    """
    Returns the current sleep time
    """
    if TEST_MODE:
        return TEST_DISPLAY_SLEEP
    return DISPLAY_SLEEP

# thread main
def display_main(firefox_num, queue, dead, logger):
    """
    Thread main for the firefox handling threads.
    Waits to receive well formatted urls from the main process
    through queue and sends them the handled firefox instance
    Finishes when dead.is_set()
    """
    logger.info("Thread %d starting", firefox_num)
    port = DEFAULT_PORT + firefox_num
    # Create repl to control firefox instance
    with Mozrepl(port=port) as mozrepl:
        current_entry = None
        change_url(mozrepl, DEFAULT_PAGE)
        logger.info(mozrepl.js("repl.whereAmI()"))
        cycles_without_new = 0
        while True:
            new_entry = None
            try:
                # get urls from the main thread
                requests = queue.get_nowait()
                logger.debug("thread %d with %d requests", firefox_num, len(requests))
                new_entry = find_best_entry(requests, current_entry)
            except Queue.Empty:
                logger.debug("thread %d queue empty", firefox_num)

            time_slept = 0
            # if the url should be changed
            if not (new_entry is None and current_entry is None):
                if new_entry:
                    # change to requested page
                    url = get_url(new_entry)
                    user_agent = get_nice_user_agent(new_entry['user_agent'])
                    logger.debug("thread %d new entry source: %s", firefox_num,
                                 new_entry['source'])
                    logger.debug("thread %d new entry user agent: %s", firefox_num,
                                 user_agent)
                    cycles_without_new = 0
                else:
                    # change to default page
                    url = DEFAULT_PAGE
                    user_agent = None
                    cycles_without_new = cycles_without_new + 1

                # if we should change
                # (that is, if we have waited enough cycles to go back to default)
                if cycles_without_new == 0 or cycles_without_new > DISPLAY_CYCLES_NO_NEW_REQUESTS:
                    logger.info("Thread %d changing url to %s", firefox_num, url)
                    change_url(mozrepl, url)
                    current_entry = new_entry
                    if user_agent:
                        # try to add the user agent to the page, waiting for when the page loads
                        logger.debug(page_complete(mozrepl))
                        while (not dead.is_set() and (time_slept < sleep_time()) and
                               (not page_complete(mozrepl))):
                            logger.debug("thread %d url not ready", firefox_num)
                            delta = 1
                            time_slept = time_slept + delta
                            time.sleep(delta)
                            add_user_agent(mozrepl, user_agent)
                        delta = 2
                        time_slept = time_slept + delta
                        if dead.is_set():
                            break
                        time.sleep(delta)
                        add_user_agent(mozrepl, user_agent)
                        logger.debug("Thread %d added user agent %s", firefox_num, user_agent)
            if dead.is_set():
                break
            time.sleep(sleep_time() - time_slept)

    logger.info("Thread %d ending", firefox_num)

def find_best_entry(requests, old):
    """
    Return the best entry in the list of sqlite objects requests given the old entry
    Best is defined as most recent request from the same browser as old or the newest
    """
    sorted(requests, key=lambda request: request['ts'], reverse=True)
    for request in requests:
        if (old and request['user_agent'] == old['user_agent'] and
                get_url(request) != get_url(old)):
            return request

    if requests:
        return requests[0]
    return None

def get_nice_user_agent(user_agent):
    """
    Return the os and browser from user_agent as a string, if present
    """
    uaobj = httpagentparser.detect(user_agent)
    res = ""
    if uaobj:
        if uaobj['os'] and uaobj['os']['name']:
            res = res + uaobj['os']['name'] + " "
        if uaobj['browser'] and uaobj['browser']['name']:
            res = res + uaobj['browser']['name']
    return res

def page_complete(mozrepl):
    """
    Return if the page in the firefox instance handled by mozrepl is ready
    """
    return 'complete' in mozrepl.js("document.readyState")

def change_url(mozrepl, url):
    """
    Change the url of the firefox instance handled by mozrepl to url
    """
    mozrepl.js("content.location.href = '%s'" % url)

def add_user_agent(mozrepl, user_agent):
    """
    Add an element to the current page of the firefox instance handled by
    mozrepl to display the given user_agent
    """
    mozrepl.js("body = content.document.body")

    mozrepl.js("div = document.createElement('div')")

    mozrepl.js("div.style.all = 'initial'")
    mozrepl.js("div.style.backgroundColor = 'white'")
    mozrepl.js("div.style.zIndex = '99999999'")
    mozrepl.js("div.style.float = 'left'")
    mozrepl.js("div.style.position = 'absolute'")
    mozrepl.js("div.style.top = '20px'")
    mozrepl.js("div.style.left = '20px'")
    mozrepl.js("div.style.backgroundColor = 'black'")

    mozrepl.js("h1 = document.createElement('h1')")
    mozrepl.js("h1.style.all = 'initial'")
    mozrepl.js("h1.style.fontSize = '4vw'")
    mozrepl.js("h1.style.fontFamily = 'Arial'")
    mozrepl.js("h1.style.color = 'white'")

    mozrepl.js("h1.innerHTML = '%s'" % user_agent)

    mozrepl.js("div.appendChild(h1)")
    mozrepl.js("body.insertBefore(div, body.firstChild)")

class GracefulKiller(object):
    """
    A class to signal when the SIGINT or SIGTERM signals are received
    Originally from
    https://stackoverflow.com/questions/18499497/how-to-process-sigterm-signal-gracefully
    """
    def __init__(self, event):
        self.dead = event
        signal.signal(signal.SIGINT, self.exit_gracefully)
        signal.signal(signal.SIGTERM, self.exit_gracefully)

    def exit_gracefully(self, *_):
        """
        Signal received, flag death
        """
        self.dead.set()

class DisplayDaemon(Daemon):
    """
    An instance of the Daemon class to allow running of the display script
    like a daemon process
    """
    def run(self, *args, **kwargs):
        if args:
            start_display(args[0])
        else:
            print "Init sleep not provided"
            sys.exit(1)

class LoggerWriter(object):
    """
    A logger handler that is intended to redirect stdin and stdout
    """
    def __init__(self, log, level):
        self.logger = log
        self.level = level

    def write(self, message):
        """
        Write message to self.logger
        """
        if message != '\n':
            self.logger.log(self.level, message)

    def flush(self):
        """
        Not implemented, allow for flushing of stdin/out
        """
        pass

def main():
    """
    Main method
    """
    parser = argparse.ArgumentParser()
    parser.add_argument("command", choices=("start", "stop", "restart", "run"))
    parser.add_argument("-i", "--init_sleep", type=int, help="initial sleep", 
                        required=False)
    args = parser.parse_args()
    if args.init_sleep is None:
        args.init_sleep = WAIT_AFTER_BOOT
    if not os.path.isdir(TMP_DIR):
        os.mkdir(TMP_DIR)
    daemon = DisplayDaemon(TMP_DIR + PID_FILE)
    if args.command == 'start':
        daemon.start(args.init_sleep)
    elif args.command == 'stop':
        daemon.stop()
    elif args.command == 'restart':
        daemon.restart()
    elif args.command == 'run':
        daemon.run(args.init_sleep)
    else:
        print "Unknown command"
        sys.exit(2)
    sys.exit(0)

if __name__ == "__main__":
    main()
        
