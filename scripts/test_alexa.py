import urllib
import urllib2
import user_agents

THREADS = 5
DELAY = 5
URLS_PER_ROUND = 5

def main():
	# get list of urls to query
	# from sqlite database?
	# get list of different user agents to user
	# set time interval
	openers = build_openers(user_agents.common_user_agents)


def build_openers(user_agents):
	openers = []
	for agent in user_agents:
		opener = urllib2.build_opener()
		opener.add_headers(['User-Agent', user_agent])
		openers.append(opener)
	return openers