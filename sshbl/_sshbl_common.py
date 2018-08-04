from .__init__ import __version__

def parse_args(description):
    import argparse

    parser = argparse.ArgumentParser(description=description)
    parser.add_argument('hosts', metavar='hostname', type=str, nargs='+',
                        help='hostnames to check')
    parser.add_argument('--max-threads', '-t', type=int, help='max number of threads to run at once')
    parser.add_argument('-v', '--version', action='version', version="sshbl %s" % __version__)
    return parser.parse_args()
