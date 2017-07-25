#!/usr/bin/env python

# Copyright Jared Moore 2017

import subprocess
import logging
from pyrepl import Mozrepl, DEFAULT_PORT
import time
import threading
import Queue

DEFAULT_PAGE = "homes.cs.washington.edu/~jlcmoore/vuExposed/index.html"
DISPLAY_SLEEP = 3
LOG_FILENAME = "/tmp/listen.log"
LOG_LEVEL = logging.INFO  # Could be e.g. "DEBUG" or "WARNING"

def main():    
    logger.info('Started')
    start()
    logger.info('Finished')
    
def start():
    num_displays = 3
    # start firefox instances
    logger.info("Starting up firefox instances")
    display_to_queue = dict()
    dead = threading.Event()
    for i in range(num_displays):
        subprocess.check_call(["firefox","-no-remote",("-P display_%d" % i),
                               ("--display=:%d" % i)])
        display_to_queue[i] = Queue()
        
    ## spawn a thread for each display and start the repl there
    for i in range(num_displays):
        t = Thread(target=display_main, args=(i, display_to_queue[i], dead))
        t.start()

    while True:
        # get the new values from the sqlite database (most probably)
        # foreach, hash the lan ip % num_display, put data value in queue
        # sleep for a bit

    dead.set()
    
# thread main
def display_main(display_num, queue, dead):
    #start repl
    with Mozrepl(DEFAULT_PORT + display_num) as mozrepl:
        logger.info(mozrepl.js("repl.whereAmI()"))
        current_entry = None
        while !dead.is_set():
            # get all the new entries in the queue
            # foreach through 
            # current entry = most recent entry where entry.uid
            # == current entry.uid || most recent entry || DEFAULT_PAGE
            url = ""
            user_agent = "blah blah placeholder"

            mozrepl.js("content.location.href = '%s'" % url)            
            mozrepl.js("body = content.document.body")
            mozrepl.js("element = document.createElement('h1')")
            mozrepl.js("element.innerHTML = '%s'" % user_agent)
            mozrepl.js("body.insertBefore(element, body)")

            # check document.readyState?
            # sleep DISPALY_SLEEP


###### SETUP
# from http://blog.scphillips.com/posts/2013/07/getting-a-python-script-to-run-in-the-background-as-a-service-on-boot/
# Make a class we can use to capture stdout and sterr in the log
class MyLogger(object):
    def __init__(self, logger, level):
        """Needs a logger and a logger level."""
        self.logger = logger
        self.level = level
        
    def write(self, message):
        # Only log if there is a message (not just a new line)
        if message.rstrip() != "":
            self.logger.log(self.level, message.rstrip())

            
if __name__ == "__main__":
    # Define and parse command line arguments
    parser = argparse.ArgumentParser(description="vuExposed listening service")
    parser.add_argument("-l", "--log",
                        help="file to write log to (default '" + LOG_FILENAME + "')")

    # If the log file is specified on the command line then override the default
    args = parser.parse_args()
    if args.log:
        LOG_FILENAME = args.log

    # Configure logging to log to a file, making a new file at midnight and
    # keeping the last 3 day's data
    # Give the logger a unique name (good practice)
    logger = logging.getLogger(__name__)
    # Set the log level to LOG_LEVEL
    logger.setLevel(LOG_LEVEL)
    # Make a handler that writes to a file, making a new file at midnight
    # and keeping 3 backups
    handler = logging.handlers.TimedRotatingFileHandler(LOG_FILENAME,
                                                        when="midnight",
                                                        backupCount=3)
    # Format each log message like this
    formatter = logging.Formatter('%(asctime)s %(levelname)-8s %(message)s')
    # Attach the formatter to the handler
    handler.setFormatter(formatter)
    # Attach the handler to the logger
    logger.addHandler(handler)
                
    # Replace stdout with logging to file at INFO level
    sys.stdout = MyLogger(logger, logging.INFO)
    # Replace stderr with logging to file at ERROR level
    sys.stderr = MyLogger(logger, logging.ERROR)
    
    main()
