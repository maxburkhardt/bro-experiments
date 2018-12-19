#!/usr/bin/env python
from broccoli import *
import time
import sys
import socket
import string

HOST="10.254.24.8"
PORT=6667
NICK="be-nice-to-max-bot"
IDENT="maxb"
REALNAME="Maximilian Burkhardt"
readbuffer="" 
s=socket.socket( )

@event
def send_message(what, channel, source):
    if source.strip() == "":
        source = "maxb"
    print 'Sending a message!'
    s.send("JOIN " + channel + "\r\n")
    print s.recv(1024)
    s.send("PRIVMSG " + channel + " :" + source + ": " + what.replace(":", "") + "\r\n")
    s.send("PART " + channel + "\r\n")
    print s.recv(1024)

def connect():
    s.connect((HOST, PORT))
    s.send("NICK %s\r\n" % NICK)
    s.send("USER %s %s botland :%s\r\n" % (IDENT, HOST, REALNAME))
    print s.recv(4096)

if __name__ == '__main__':
    bc = Connection("127.0.0.1:47757")
    connect()
    while True:
        bc.processInput()
        time.sleep(0.5)
