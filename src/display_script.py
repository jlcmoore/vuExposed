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
import urllib2
from adblockparser import AdblockRules
import httpagentparser
from pyrepl import Mozrepl, DEFAULT_PORT
from daemon import Daemon

TMP_DIR = '/tmp/display/'
ACCEPTABLE_HTTP_STATUSES = [200, 201]
BLOCK_FILES = ["block_lists/easylist.txt","block_lists/unified_hosts_and_porn.txt"]
DEFAULT_PAGE = "file:///home/listen/Documents/vuExposed/docs/monitor.html"
DISPLAY_SLEEP = 10
DISPLAY_CYCLES_NO_NEW_REQUESTS = 2
DOCTYPE_PATTERN = re.compile("!doctype html", re.IGNORECASE)
FILTER_LOAD_URL_TIMEOUT = .5
HTML_MIME = "text/html"
IGNORE_USER_AGENTS = ['Python-urllib/1.17','Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:54.0) Gecko/20100101 Firefox/54.0']
INIT_SLEEP = 5
IS_PROXY = True
LOCAL_IP_PATTERN = re.compile(r"192\.168\.1\.\d{1,3}")
LOG_FILENAME = "listen.log"
LOG_LEVEL = logging.DEBUG  # Could be e.g. "DEBUG" or "WARNING"
MACHINE_IP = '192.168.1.125'
MACHINE_PROXY_PORT = 10000
NUM_DISPLAYS = 3
PID_FILE = 'display_daemon.pid'
PORT_MIRRORING = True
SQL_DATABASE = "/var/db/httptosql.sqlite"
TABLE_NAME = "http"
QUERY_NO_END = "select ts, source, host, uri, user_agent,referrer, source_port, dest_port from " + TABLE_NAME + " WHERE ts > ?"
QUERY = QUERY_NO_END + ";"
DELETE_QUERY = "delete from " + TABLE_NAME + " where ts < ?;"

TIME_FORMAT = "%Y/%m/%d %H:%M:%S"
TEST_MODE = False
TEST_DISPLAY_SLEEP = DISPLAY_SLEEP
TEST_QUERY = QUERY_NO_END + " and ts < ?;"
TEST_SQL_DATABASE = "assets/test.sqlite"
TEST_TABLE_NAME = "requests"
TEST_TIME_START = "2017/08/01 15:48:01"


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
        # 'g,x,y,w,h'
        # the hack here to 10 10 allows the windows to resize to the monitor
        # in which they are placed
        m = monitor_list[monitor_counter]
        geometry = "0,%s,%s,%s,%s" % (m.x_offset,m.y_offset,10,10)
        logger.info("firefox geometry " + geometry)
        pid = proc.pid
        window_id = get_window_id(pid)
        if not window_id:
            logger.error("Could not get window id of firefox instance; dying")
            sys.exit(1)
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
    logger = logging.getLogger(__name__)
    logger.setLevel(LOG_LEVEL)
    handler = logging.handlers.TimedRotatingFileHandler(log_name,
                                                        when="midnight",
                                                        backupCount=3)
    formatter = logging.Formatter('%(asctime)s %(levelname)-8s %(message)s')
    handler.setFormatter(formatter)
    logger.addHandler(handler)
                
    # Replace stdout with logging to file at INFO level
    sys.stdout = LoggerWriter(logger, logging.INFO)
    # Replace stderr with logging to file at ERROR level
    sys.stderr = LoggerWriter(logger, logging.ERROR)
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
            # spawn a thread for each display and start the repl there
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
        for thread in threads:
            thread.join()
        for firefox in firefox_procs:
            os.killpg(os.getpgid(firefox.pid), signal.SIGTERM)
        logger.info("Finished waiting for threads")        
        logger.info("Threads finished")

def query_for_requests(last_time, new_last_time, c):
    rows = []
    try:
        if TEST_MODE:
            c.execute(TEST_QUERY, (last_time, new_last_time,))
        else:
            c.execute(QUERY, (last_time,))
        rows = c.fetchall()
    except Exception, err:
        logger.error("Sqlite error: %s", err)
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
        url = get_url(request)
        logger.debug("Potential request for %s from src ip %s", url, request['source'])
        if (is_wifi_request(request) and 
                (not rules.should_block(url)) and
                can_show_url(url)):
            to_firefox = hash(request['user_agent']) % num_firefox
            inter_lists[to_firefox].append(request)
            logger.info("Added request for %s to browswer %d", url, to_firefox)

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

def can_show_url(url):
    try:
        res = urllib2.urlopen(url, timeout=FILTER_LOAD_URL_TIMEOUT)
        http_message = res.info()
        full = http_message.type # 'text/plain'
        code = res.getcode()
        if full == HTML_MIME and code in ACCEPTABLE_HTTP_STATUSES:
            data = res.read()
            return re.search(DOCTYPE_PATTERN, data)
    except (urllib2.HTTPError, urllib2.URLError) as error:
        logging.error('url %s open error: %s', url, error)
    except socket.timeout:
        logging.error('socket timed out for url %s', url)
    return False
        
def is_wifi_request(request):
    ip = request['source']
    if PORT_MIRRORING:
        result = (not re.search(MACHINE_IP, ip) and
         not request['user_agent'] in IGNORE_USER_AGENTS)
    else:
        result = (re.search(MACHINE_IP, ip) and
         request['source_port'] == MACHINE_PROXY_PORT)
    return result

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
        cycles_without_new = 0
        while True:
            new_entry = None
            try:
                # TODO: change this to get no wait and then sleep, add user agent loop for display sleep time
                requests = queue.get_nowait()
                logger.debug("thread %d with %d requests", firefox_num, len(requests))
                new_entry = find_best_entry(requests, current_entry)
            except Queue.Empty:
                logger.debug("thread %d queue empty", firefox_num)
            
            time_slept = 0
            if not (new_entry == None and current_entry == None):
                if new_entry:
                    url = get_url(new_entry)
                    user_agent = get_nice_user_agent(new_entry['user_agent'])
                    logger.debug("thread %d new entry source: %s", firefox_num, 
                        new_entry['source'])
                    logger.debug("thread %d new entry user agent: %s", firefox_num, 
                        user_agent)
                    cycles_without_new = 0
                else:
                    url = DEFAULT_PAGE
                    user_agent = None
                    cycles_without_new = cycles_without_new + 1  

                if cycles_without_new == 0 or cycles_without_new > DISPLAY_CYCLES_NO_NEW_REQUESTS:
                    logger.info("Thread %d changing url to %s", firefox_num, url)
                    change_url(mozrepl, url)
                    current_entry = new_entry
                    if user_agent:
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

def get_nice_user_agent(user_agent):
    uaobj = httpagentparser.detect(new_entry['user_agent'])
    res = ""
    if uaobj:
        if uaobj['os'] and uaobj['os']['name']:
            res = res + uaobj['os']['name'] + " "
        if uaobj['browser'] and uaobj['browser']['name']:
            res = res + uaobj['browser']['name']
    return res

def page_complete(mozrepl):
    return 'complete' in mozrepl.js("document.readyState")

def change_url(mozrepl, url):
    mozrepl.js("content.location.href = '%s'" % url)    
    
def add_user_agent(mozrepl, user_agent):
    mozrepl.js("body = content.document.body")

    mozrepl.js("div = document.createElement('div')")
    
    mozrepl.js("div.style.all = 'initial'")    
    mozrepl.js("div.style.backgroundColor = 'white'")
    mozrepl.js("div.style.zIndex = '99999999'")
    mozrepl.js("div.style.float = 'left'")
    mozrepl.js("div.style.position = 'absolute'")

    mozrepl.js("h1 = document.createElement('h1')")
    mozrepl.js("h1.style.all = 'initial'")
    mozrepl.js("h1.style.fontSize = '4vw'")
    mozrepl.js("h1.style.fontFamily = 'Arial'")
    mozrepl.js("h1.style.color = 'black'")
    

    mozrepl.js("h1.innerHTML = '%s'" % user_agent)

    mozrepl.js("div.appendChild(h1)")
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

class LoggerWriter:
    def __init__(self, logger, level): 
        self.logger = logger
        self.level = level 

    def write(self, message):
        if message != '\n':
            self.logger.log(self.level, message)

    def flush(self): 
        pass

# TODO: turn into a class and don't use this logger


if __name__ == "__main__":
    if not os.path.isdir(TMP_DIR):
        os.mkdir(TMP_DIR)
    logger = create_logger(TMP_DIR + sys.argv[1] + "_" + LOG_FILENAME)
    daemon = DisplayDaemon(TMP_DIR + PID_FILE)
    if len(sys.argv) == 2:
        if 'start' == sys.argv[1]:
            daemon.start()
        elif 'stop' == sys.argv[1]:
            daemon.stop()
        elif 'restart' == sys.argv[1]:
            daemon.restart()
        elif 'run' == sys.argv[1]:
            daemon.run()
        else:
            print "Unknown command"
            sys.exit(2)
        sys.exit(0)
    else:
        print "usage: %s start|stop|restart|run" % sys.argv[0]
        sys.exit(2)