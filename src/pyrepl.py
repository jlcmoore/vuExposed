# shamelessly taken from https://github.com/bard/mozrepl/wiki/Pyrepl
import sys, re
from telnetlib import Telnet

DEFAULT_PORT = 4240

class Mozrepl(object):
    def __init__(self, ip="127.0.0.1", port=DEFAULT_PORT):
        self.ip = ip
        self.port = port
        self.prompt = b"repl>"

    def __enter__(self):
        self.t = Telnet(self.ip, self.port)
        intro = self.t.read_until(self.prompt, 1)
        if not intro.endswith(self.prompt):
            self.prompt = re.search(br"repl\d+>", intro).group(0)
            print("Waited due to nonstandard prompt:", self.prompt.decode())
        return self

    def __exit__(self, type, value, traceback):
        self.t.close()
        del self.t

    def js(self, command):
        self.t.write(command.encode() + b"\n")
        return self.t.read_until(self.prompt).decode()
