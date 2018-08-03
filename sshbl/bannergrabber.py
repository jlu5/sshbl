#!/usr/bin/env python3

import sys
import socket
import re
import traceback

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
        traceback.print_exc()
        return

    match = SSH_BANNER_REGEX.match(firstline)

    if not match:
        return (ip, port, firstline, None, None)
    return (ip, port, *match.groups())

def grab_ssh_version(ip, port=22):
    """
    Grabs SSH version from an IP and port.
    """
    print("Connecting to %s on port %s" % (ip, port))
    s = socket.socket()
    s.settimeout(5)
    try:
        s.connect((ip, port))
    except socket.error:
        print(ip, "timed out")
        return

    data = s.recv(2048)
    s.shutdown(socket.SHUT_WR)
    s.close()
    print(ip, data)

    return parse_ssh_version(ip, port, data)

MAX_THREADS = 5

def main():
    import concurrent.futures
    ips = sys.argv[1]

    # We can use a with statement to ensure threads are cleaned up promptly
    with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_THREADS) as executor:
        for result in executor.map(grab_ssh_version, ips, timeout=None, chunksize=1):
            print(result)

if __name__ == '__main__':
    main()

