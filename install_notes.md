
Make sure connected to internet

/lib/systemd/system/listen.service

Start bro:
$ sudo /usr/local/bro/bin/broctl
->     deploy

Writes to /var/db/httptosql.sqlite

Bro scripts:
/usr/local/bro/share/bro/site/httptosql.bro
/usr/local/bro/share/bro/site/local.bro
	Loads the former


Limit shown http requests to
source is from lan
192.168.1.*


http response where content type is text/html
from that get the page requested

check if local:
from https://www.bro.org/sphinx-git/httpmonitor/index.html
Site::is_local_addr(c$id$resp_h)


firefox disable crash dialog
https://support.mozilla.org/en-US/questions/951221
about:config
>browser.sessionstore.resume_from_crash
 toolkit.startup.max_resumed_crashes
 accessibility.blockautorefresh
 browser.cache.disk.enable

also .mozilla/firefox/profile/userChrome.css