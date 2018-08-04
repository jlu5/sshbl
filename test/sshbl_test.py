#!/usr/bin/env python3
import unittest
import inspect
import logging

from sshbl.sshbl import *

class SSHBLTest(unittest.TestCase):
    def assertBlacklisted(self, data, threshold=0):
        result_tuple = parse_ssh_version(inspect.stack()[1][3], '', data)
        self.assertTrue(is_blacklisted_version(result_tuple, threshold=threshold))

    def assertNotBlacklisted(self, data, threshold=0):
        result_tuple = parse_ssh_version(inspect.stack()[1][3], '', data)
        self.assertFalse(is_blacklisted_version(result_tuple, threshold=threshold))

    def testDropbear(self):
        self.assertBlacklisted(b'SSH-2.0-dropbear_0.52\r\n')
        self.assertBlacklisted(b'SSH-2.0-dropbear_0.51\r\n')
        self.assertBlacklisted(b'SSH-2.0-dropbear_2013.62\r\n\x00\x00\x01\x84\n\x14\x91\xc6\x91\x1d\x1a\xdc\x83\xbb\xdc\xe9\xa0V\n\x1f\xdb\xd3\x00\x00\x00\xa6curve25519-sha256@libssh.org,ecdh-sha2-nistp521,ecdh-sha2-nistp384,ecdh-sha2-nistp256,diffie-hellman-group1-sha1,diffie-hellman-group14-sha1,kexguess2@matt.ucc.asn.au\x00\x00\x00\x07ssh-rsa\x00\x00\x00\x1eaes128-ctr,3des-ctr,aes256-ctr\x00\x00\x00\x1eaes128-ctr,3des-ctr,aes256-ctr\x00\x00\x00%hmac-sha2-256,hmac-sha2-512,hmac-sha1\x00\x00\x00%hmac-sha2-256,hmac-sha2-512,hmac-sha1\x00\x00\x00\x04none\x00\x00\x00\x04none\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xe5j\xb6\\\xf6\xba\x18M=l')
        self.assertBlacklisted(b'SSH-2.0-dropbear_2013.62\r\n\x00\x00\x01\x84\n\x14\x0e\x13\xc5\x99\xb1\xcd\xd2\x06\x8fK\xb5\xe4r\xb9N\xb9\x00\x00\x00\xa6curve25519-sha256@libssh.org,ecdh-sha2-nistp521,ecdh-sha2-nistp384,ecdh-sha2-nistp256,diffie-hellman-group1-sha1,diffie-hellman-group14-sha1,kexguess2@matt.ucc.asn.au\x00\x00\x00\x07ssh-rsa\x00\x00\x00\x1eaes128-ctr,3des-ctr,aes256-ctr\x00\x00\x00\x1eaes128-ctr,3des-ctr,aes256-ctr\x00\x00\x00%hmac-sha2-256,hmac-sha2-512,hmac-sha1\x00\x00\x00%hmac-sha2-256,hmac-sha2-512,hmac-sha1\x00\x00\x00\x04none\x00\x00\x00\x04none\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00nV\xbch\xb2\xbb2\xff\xdd?')

        self.assertNotBlacklisted(b'SSH-2.0-dropbear_2014.65\r\n')
        self.assertNotBlacklisted(b'SSH-2.0-dropbear_2016.74\r\n\x00\x00\x01\x94\x04\x14\xa5o\x05\x9c\xb3\xfb\x00\x1aW\x92BBf !\x93\x00\x00\x00Pdiffie-hellman-group14-sha1,diffie-hellman-group1-sha1,kexguess2@matt.ucc.asn.au\x00\x00\x00\x07ssh-rsa\x00\x00\x00gaes128-ctr,aes256-ctr,aes128-cbc,aes256-cbc,twofish256-cbc,twofish-cbc,twofish128-cbc,3des-ctr,3des-cbc\x00\x00\x00gaes128-ctr,aes256-ctr,aes128-cbc,aes256-cbc,twofish256-cbc,twofish-cbc,twofish128-cbc,3des-ctr,3des-cbc\x00\x00\x00\x12hmac-sha1,hmac-md5\x00\x00\x00\x12hmac-sha1,hmac-md5\x00\x00\x00\x04none\x00\x00\x00\x04none\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xef\xcf\xd9"')
        self.assertNotBlacklisted(b'SSH-2.0-dropbear_2018.76\r\n')

    def testOpenSSH(self):
        # TODO: there are no rules targetting OpenSSH yet
        self.assertNotBlacklisted(b'SSH-2.0-OpenSSH_7.4p1 Debian-10+deb9u3\n')
        self.assertNotBlacklisted(b'SSH-2.0-OpenSSH_6.0p1 Debian-4+deb7u6\r\n')
        self.assertNotBlacklisted(b'SSH-2.0-OpenSSH_6.0p1')
        self.assertNotBlacklisted(b'SSH-2.0-OpenSSH_6.6.1\r\n')

    def testROSSSH(self):
        self.assertBlacklisted(b'SSH-2.0-ROSSSH\r\n')

    def testArbitrarySingleWord(self):
        self.assertNotBlacklisted(b'SSH-2.0-abcd\r\n')
        self.assertNotBlacklisted(b'SSH-2.0-abcd\n')
        self.assertNotBlacklisted(b'SSH-2.0-EEeeEE\r\n')
        self.assertNotBlacklisted(b'SSH-2.0-100test\r\n')
        self.assertNotBlacklisted(b'SSH-2.0-BEST0test\n')

    def testArbitraryDouble(self):
        self.assertNotBlacklisted(b'SSH-2.0-SSHtest-1.0\n')
        self.assertNotBlacklisted(b'SSH-2.0-SSHtest_0.56\n')
        self.assertNotBlacklisted(b'SSH-2.0-SSHtest-3.0.2a\n')
        self.assertNotBlacklisted(b'SSH-2.0-1x1x-1.4\n')
        self.assertNotBlacklisted(b'SSH-2.0-2x2x-0.12\n')
        self.assertNotBlacklisted(b'SSH-2.0-testtttt_1.0.2050\n')

    def testThreshold(self):
        self.assertBlacklisted(b'SSH-2.0-dropbear_0.52\r\n', threshold=-10)
        self.assertNotBlacklisted(b'SSH-2.0-dropbear_0.52\r\n', threshold=-30)
        self.assertNotBlacklisted(b'SSH-2.0-dropbear_0.52\r\n', threshold=-500)
        self.assertBlacklisted(b'SSH-2.0-ROSSSH\r\n', threshold=0)
        self.assertNotBlacklisted(b'SSH-2.0-ROSSSH\r\n', threshold=-5)
        self.assertNotBlacklisted(b'SSH-2.0-ROSSSH\r\n', threshold=-10)

if __name__ == '__main__':
    unittest.main(verbosity=2)
