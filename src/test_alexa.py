#!/usr/bin/env python

import random
import socket
import sys
import time
import threading
import urllib2
from user_agents import common_user_agents
from no_https_hosts import top_1000_no_https_hosts

DELAY = 15
ROUNDS = 1
SOCKET_TIMEOUT = 2
URLS_PER_ROUND = 50

def main(rounds=ROUNDS, urls=URLS_PER_ROUND):
	for i in range(rounds):
                print "round number %d" % i
		for j in range(urls):
			user_agent = common_user_agents[random.randint(0, len(common_user_agents) - 1)]
			url = top_1000_no_https_hosts[random.randint(0, len(top_1000_no_https_hosts) - 1)]
			num = "%d %d" % (i, j)
			thread = threading.Thread(target=open_page, args=(num, user_agent, url))
			thread.daemon = True
			thread.start()
		time.sleep(DELAY)

def open_page(num, user_agent, url):
	try:
		opener = urllib2.build_opener()
		opener.addheaders = [('User-Agent', user_agent)]
		opener.open(url)
		print '%s opened %s' % (num, url)
	except (urllib2.HTTPError, urllib2.URLError) as error:
		print '%s url %s open error: %s' % (num, url, error)
	except socket.timeout:
		print '%s timeout' % num
		
if __name__ == "__main__":
        if len(sys.argv) > 1:
                main(int(sys.argv[1]), int(sys.argv[2]))
        else:
	        main()
