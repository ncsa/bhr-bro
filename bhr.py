#!/usr/bin/env python
import sys
from bhr_client.rest import login_from_env

def bhr(src, comment):
    client = login_from_env()
    block = client.block(cidr=src, source='bro', why=comment, duration=600, autoscale=1)
    return True

def main():
    lines = sys.stdin.read().strip().split("\n")
    src, note, msg, sub = lines

    #sub is not currently used
    comment = "%s: %s" % (note, msg)

    bhr(src, comment)

if __name__ == "__main__":
    main()
