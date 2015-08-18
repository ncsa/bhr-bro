#!/usr/bin/env python

import json
import os
import signal
import sys
import time

SLEEP = 1
QDIR = "/var/lib/brobhrqueue"

import logging
import logging.handlers

formatter = logging.Formatter('%(name)s: %(levelname)s %(message)s')
logging.basicConfig(level=logging.DEBUG, format="%(name)s %(levelname)s %(message)s")
handler = logging.handlers.SysLogHandler(address='/dev/log')
handler.setFormatter(formatter)
handler.setLevel(logging.INFO)
log = logging.getLogger("BHR_CLIENT")
log.addHandler(handler)
logging.getLogger("requests").setLevel(logging.WARNING)

def block(ip, comment, duration):
    from bhr_client.rest import login_from_env
    client = login_from_env()
    duration = int(float(duration)) # Bro sends it as ##.0
    block = client.block(cidr=ip, source='bro', why=comment, duration=duration, autoscale=1)
    return True

def queue(ip, comment, duration):
    from dirq.QueueSimple import QueueSimple
    dirq = QueueSimple(QDIR)
    rec = dict(ip=ip, comment=comment, duration=duration, ts=time.time())
    dirq.add(json.dumps(rec))
    return True

def run_queue_once():
    from dirq.QueueSimple import QueueSimple
    dirq = QueueSimple(QDIR)
    dirq.purge(30,60)
    did_work = False
    for name in dirq:
        if not dirq.lock(name):
            continue
        data = dirq.get(name)
        print data
        item = json.loads(data)

        signal.alarm(15)
        queue_ts = item['ts']
        start = time.time()

        try :
            block(item['ip'], item['comment'], item['duration'])
        except Exception, e:
            #Was this a whitelisted host or similarly invalid request
            #Versus a server error?
            if hasattr(e, 'response') and e.response.status_code == 400 and 'non_field_errors' in e.response.json():
                log.info("Ignored API Error %s", e.response.json())
            else:
                log.exception("API Error")
                raise
        end = time.time()
        signal.alarm(0)

        dirq.remove(name)

        log.info("block ip=%s queue_latency=%0.2f api_latency=%0.2f", item['ip'], start-queue_ts, end-start)
        did_work = True

    return did_work

def run_queue():
    #run queue for 10 minutes
    for x in range(60*10/SLEEP):
        did_work = run_queue_once()
        if not did_work:
            time.sleep(SLEEP)

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
