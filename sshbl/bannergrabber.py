#!/usr/bin/env python3

import sys
import socket
import re
import traceback

from ._sshbl_common import *

# e.g. SSH-1.99-OpenSSH_5.1
#      SSH-2.0-dropbear_2013.62

SSH_BANNER_REGEX = re.compile(r"^SSH-(?P<sshversion>[0-9.]+?)-(?P<product>[0-9a-zA-Z]+)(?:[-_](?P<version>.+))?")

def parse_ssh_version(ip, port, data):
    """
    Given IP, port, and raw data (bytes), returns the parsed SSH version.
    """
    try:
        firstline = data.splitlines()[0]
    except (IndexError, ValueError):
        firstline = data
    try:
        firstline = firstline.decode()
    except ValueError:
        log.exception("Failed to decode SSH banner")

    match = SSH_BANNER_REGEX.match(firstline)

    if not match:
        return (ip, port, firstline, None, None)
    return (ip, port, *match.groups())

def grab_ssh_version(ip, port=22):
    """
    Grabs SSH version from an IP and port.
    """
    log.info("Connecting to %s on port %s", ip, port)
    s = socket.socket()
    s.settimeout(5)
    try:
        s.connect((ip, port))
    except socket.error:
        log.info("%s timed out", ip)
        return

    data = s.recv(2048)
    s.shutdown(socket.SHUT_WR)
    s.close()
    log.debug("%s got raw data %s", ip, data)

    return parse_ssh_version(ip, port, data)

def main():
    import concurrent.futures
    args = parse_args('Outputs the SSH banner of a remote host')

    log.info("Using up to %s threads", args.max_threads)
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.max_threads) as executor:
        for result in executor.map(grab_ssh_version, args.hosts, chunksize=1):
            print(result)

if __name__ == '__main__':
    main()

