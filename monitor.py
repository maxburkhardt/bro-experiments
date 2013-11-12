#!/usr/bin/env python
from broccoli import *
import time
import socket

@event
def communicate(status, who):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect(("alakazam.internal", 9000))
    s.sendall(str(status) + "|" + str(who))
    s.close()
    print status

if __name__ == '__main__':
    bc = Connection("127.0.0.1:47757")
    while True:
        bc.processInput()
        time.sleep(5)
