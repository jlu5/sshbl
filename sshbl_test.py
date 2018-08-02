import unittest
import inspect
import logging

from sshbl import *

class SSHBLTest(unittest.TestCase):

    def assertSSHEqual(self, data, sshversion, product, version):
        result_tuple = parse_ssh_version(inspect.stack()[1][3], '', data)
        ip, port, r_sshversion, r_product, r_version = result_tuple

        self.assertEqual(r_sshversion, sshversion)
        self.assertEqual(r_product, product)
        self.assertEqual(r_version, version)

    def testDropbear(self):
        self.assertSSHEqual(b'SSH-2.0-dropbear_0.52\r\n', '2.0', 'dropbear', '0.52')
        self.assertSSHEqual(b'SSH-2.0-dropbear_0.51\r\n', '2.0', 'dropbear', '0.51')
        self.assertSSHEqual(b'SSH-2.0-dropbear_2013.62\r\n\x00\x00\x01\x84\n\x14\x91\xc6\x91\x1d\x1a\xdc\x83\xbb\xdc\xe9\xa0V\n\x1f\xdb\xd3\x00\x00\x00\xa6curve25519-sha256@libssh.org,ecdh-sha2-nistp521,ecdh-sha2-nistp384,ecdh-sha2-nistp256,diffie-hellman-group1-sha1,diffie-hellman-group14-sha1,kexguess2@matt.ucc.asn.au\x00\x00\x00\x07ssh-rsa\x00\x00\x00\x1eaes128-ctr,3des-ctr,aes256-ctr\x00\x00\x00\x1eaes128-ctr,3des-ctr,aes256-ctr\x00\x00\x00%hmac-sha2-256,hmac-sha2-512,hmac-sha1\x00\x00\x00%hmac-sha2-256,hmac-sha2-512,hmac-sha1\x00\x00\x00\x04none\x00\x00\x00\x04none\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xe5j\xb6\\\xf6\xba\x18M=l', '2.0', 'dropbear', '2013.62')
        self.assertSSHEqual(b'SSH-2.0-dropbear_2013.62\r\n\x00\x00\x01\x84\n\x14\x0e\x13\xc5\x99\xb1\xcd\xd2\x06\x8fK\xb5\xe4r\xb9N\xb9\x00\x00\x00\xa6curve25519-sha256@libssh.org,ecdh-sha2-nistp521,ecdh-sha2-nistp384,ecdh-sha2-nistp256,diffie-hellman-group1-sha1,diffie-hellman-group14-sha1,kexguess2@matt.ucc.asn.au\x00\x00\x00\x07ssh-rsa\x00\x00\x00\x1eaes128-ctr,3des-ctr,aes256-ctr\x00\x00\x00\x1eaes128-ctr,3des-ctr,aes256-ctr\x00\x00\x00%hmac-sha2-256,hmac-sha2-512,hmac-sha1\x00\x00\x00%hmac-sha2-256,hmac-sha2-512,hmac-sha1\x00\x00\x00\x04none\x00\x00\x00\x04none\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00nV\xbch\xb2\xbb2\xff\xdd?', '2.0', 'dropbear', '2013.62')
        self.assertSSHEqual(b'SSH-2.0-dropbear_2013.62\r\n\x00\x00\x01\x84\n\x14\xc2\xf3\xb5\x0f\xf1\xea\x90\x9f\xba\x16\x8al\x14\xed\xd4\xa3\x00\x00\x00\xa6curve25519-sha256@libssh.org,ecdh-sha2-nistp521,ecdh-sha2-nistp384,ecdh-sha2-nistp256,diffie-hellman-group1-sha1,diffie-hellman-group14-sha1,kexguess2@matt.ucc.asn.au\x00\x00\x00\x07ssh-rsa\x00\x00\x00\x1eaes128-ctr,3des-ctr,aes256-ctr\x00\x00\x00\x1eaes128-ctr,3des-ctr,aes256-ctr\x00\x00\x00%hmac-sha2-256,hmac-sha2-512,hmac-sha1\x00\x00\x00%hmac-sha2-256,hmac-sha2-512,hmac-sha1\x00\x00\x00\x04none\x00\x00\x00\x04none\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x005\xfe\x01\x1c+\xcbY\x02k\x14', '2.0', 'dropbear', '2013.62')

    def testOpenSSH(self):
        self.assertSSHEqual(b'SSH-2.0-OpenSSH_7.4p1 Debian-10+deb9u3\n', '2.0', 'OpenSSH', '7.4p1 Debian-10+deb9u3')
        self.assertSSHEqual(b'SSH-2.0-OpenSSH_6.0p1 Debian-4+deb7u6\r\n', '2.0', 'OpenSSH', '6.0p1 Debian-4+deb7u6')
        self.assertSSHEqual(b'SSH-2.0-OpenSSH_6.0p1', '2.0', 'OpenSSH', '6.0p1')
        self.assertSSHEqual(b'SSH-2.0-OpenSSH_6.6.1\r\n', '2.0', 'OpenSSH', '6.6.1')

    def testROSSSH(self):
        self.assertSSHEqual(b'SSH-2.0-ROSSSH\r\n', '2.0', 'ROSSSH', None)

    def testArbitrarySingleWord(self):
        self.assertSSHEqual(b'SSH-2.0-abcd\r\n', '2.0', 'abcd', None)
        self.assertSSHEqual(b'SSH-2.0-abcd\n', '2.0', 'abcd', None)
        self.assertSSHEqual(b'SSH-2.0-EEeeEE\r\n', '2.0', 'EEeeEE', None)
        self.assertSSHEqual(b'SSH-2.0-100test\r\n', '2.0', '100test', None)
        self.assertSSHEqual(b'SSH-2.0-BEST0test\n', '2.0', 'BEST0test', None)

    def testArbitraryDouble(self):
        self.assertSSHEqual(b'SSH-2.0-SSHtest-1.0\n', '2.0', 'SSHtest', '1.0')
        self.assertSSHEqual(b'SSH-2.0-SSHtest_0.56\n', '2.0', 'SSHtest', '0.56')
        self.assertSSHEqual(b'SSH-2.0-SSHtest-3.0.2a\n', '2.0', 'SSHtest', '3.0.2a')
        self.assertSSHEqual(b'SSH-2.0-1x1x-1.4\n', '2.0', '1x1x', '1.4')
        self.assertSSHEqual(b'SSH-2.0-2x2x-0.12\n', '2.0', '2x2x', '0.12')
        self.assertSSHEqual(b'SSH-2.0-testtttt_1.0.2050\n', '2.0', 'testtttt', '1.0.2050')

if __name__ == '__main__':
    unittest.main(verbosity=2)
