import functools
from pkg_resources import parse_version

from .bannergrabber import *

# Fills in all comparison functions automatically given __eq__ and one of __lt__, __le__, __gt__, __ge__
@functools.total_ordering
class ComparableVersion():
	"""
	Representation of a program version that can be compared to a string or another ComparableVersion instance.
	"""
	def __init__(self, versionstr):
		self.version = versionstr

	def __eq__(self, other):
		if isinstance(other, str):
			return self.version == other
		return self.version == other.version

	def __lt__(self, other):
		if isinstance(other, str):
			return parse_version(self.version) < parse_version(other)
		return parse_version(self.version) < parse_version(other.version)

def blacklist_score(version_tuple):
	"""
	Returns a blacklist score given the version tuple (higher is better)
	"""
	# Note: sshversion is SSH version (1.99, 2.0), version is SSHd version
	_, _, sshversion, product, version = version_tuple
	c_sshversion = ComparableVersion(sshversion)
	if version is None:
		version = ''
	c_version = ComparableVersion(version)

	score = 0

	if "Debian" in version:  # Vendor strings
		score += 20

	# SSHv1 is insecure / obsolete
	if c_sshversion <= "1.99":
		score -= 10

	# Many drones running dropbear 2013.62 (5 years old) and 0.52 (10 years old!!)
	if "dropbear" in product:
		if c_version < "2014":
			score -= 10
		if c_version <= "0.53":
			score -= 20

	# Also many compromised MikroTik devices
	if "ROSSSH" in product:
		score -= 5

	# TODO: check for common OpenSSH versions on abused hosts

	return score

def is_blacklisted_version(version_tuple, threshold=0):
	"""
	Returns whether the blacklist score for the version tuple is < than the threshold.
	"""
	score = blacklist_score(version_tuple)
	print(version_tuple, "score:", score)
	return score < threshold

def scan(ip, port=22):
	"""
	Scans a hostname and port and returns a blacklist score.
	"""
	versionpair = grab_ssh_version(ip, port)
	return is_blacklisted_version(version_tuple)
