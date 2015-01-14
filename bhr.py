#!/usr/bin/env python

import json
import os
import signal
import sys
import time

SLEEP = 2
QDIR = "/var/lib/brobhrqueue"

def block(ip, comment, duration):
    from bhr_client.rest import login_from_env
    client = login_from_env()
    duration = int(duration) # Bro sends it as ##.0
    block = client.block(cidr=ip, source='bro', why=comment, duration=duration, autoscale=1)
    return True

def queue(ip, comment, duration):
    from dirq.QueueSimple import QueueSimple
    dirq = QueueSimple(QDIR)
    rec = dict(ip=ip, comment=comment, duration=duration)
    dirq.add(json.dumps(rec))
    return True

def run_queue_once():
    from dirq.QueueSimple import QueueSimple
    dirq = QueueSimple(QDIR)
    dirq.purge(30,60)
    for name in dirq:
        if not dirq.lock(name):
            continue
        data = dirq.get(name)
        print data
        item = json.loads(data)
        signal.alarm(15)
        block(**item)
        signal.alarm(0)
        dirq.remove(name)

def run_queue():
    #run queue for 10 minutes
    for x in range(60*10/SLEEP):
        time.sleep(SLEEP)
        run_queue_once()

def main():
    try:
        mode = sys.argv[1]
    except IndexError:
        sys.stderr.write("Usage: %s <block|queue|run_queue>\n" % sys.argv[0])
        sys.exit(1)

    if mode in ['block', 'queue']:
        lines = sys.stdin.read().strip().split("\n")
        src, note, msg, sub, duration = lines

        #sub is not currently used
        comment = "%s: %s" % (note, msg)

        if mode == "block":
            block(src, comment, duration)
        elif mode == "queue":
            queue(src, comment, duration)

    if mode == 'run_queue':
        run_queue()

if __name__ == "__main__":
    main()
