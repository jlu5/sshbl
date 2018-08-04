import logging
from .__init__ import __version__

logging.basicConfig()
log = logging.getLogger("sshbl")
log.setLevel(logging.INFO)

def parse_args(description):
    import argparse

    parser = argparse.ArgumentParser(description=description)
    parser.add_argument('hosts', metavar='hostname', type=str, nargs='+',
                        help='hostnames to check')
    parser.add_argument('--max-threads', '-t', type=int, help='max number of threads to run at once', default=5)
    parser.add_argument('-v', '--version', action='version', version="sshbl %s" % __version__)
    parser.add_argument('-V', '--verbose', action='store_true', help='Determines whether verbose mode should be used')
    args = parser.parse_args()

    if args.verbose:
        log.setLevel(logging.DEBUG)

    return args

