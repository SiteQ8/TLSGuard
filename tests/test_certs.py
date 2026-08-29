import unittest

from tlsguard.audit import parse_target
from tlsguard.certs import hostname_matches, is_self_signed


def cert(subject_cn=None, issuer_cn=None, sans=None):
    d = {}
    if subject_cn:
        d["subject"] = ((("commonName", subject_cn),),)
    if issuer_cn:
        d["issuer"] = ((("commonName", issuer_cn),),)
    if sans:
        d["subjectAltName"] = tuple(("DNS", s) for s in sans)
    return d


class TestHostnameMatch(unittest.TestCase):
    def test_exact(self):
        self.assertTrue(hostname_matches(cert(sans=["example.com"]), "example.com"))

    def test_wildcard(self):
        c = cert(sans=["*.example.com"])
        self.assertTrue(hostname_matches(c, "api.example.com"))
        self.assertFalse(hostname_matches(c, "example.com"))
        self.assertFalse(hostname_matches(c, "a.b.example.com"))

    def test_no_match(self):
        self.assertFalse(hostname_matches(cert(sans=["other.com"]), "example.com"))

    def test_falls_back_to_cn(self):
        self.assertTrue(hostname_matches(cert(subject_cn="example.com"), "example.com"))


class TestSelfSigned(unittest.TestCase):
    def test_self_signed(self):
        c = cert(subject_cn="me", issuer_cn="me")
        self.assertTrue(is_self_signed(c))

    def test_not_self_signed(self):
        c = cert(subject_cn="example.com", issuer_cn="Some CA")
        self.assertFalse(is_self_signed(c))


class TestParseTarget(unittest.TestCase):
    def test_plain_host(self):
        self.assertEqual(parse_target("example.com"), ("example.com", 443))

    def test_host_with_port(self):
        self.assertEqual(parse_target("example.com:8443"), ("example.com", 8443))

    def test_strips_scheme_and_path(self):
        self.assertEqual(parse_target("https://example.com/login"), ("example.com", 443))

    def test_ipv6_bracket(self):
        self.assertEqual(parse_target("[2606:2800:220:1::1]:443"), ("2606:2800:220:1::1", 443))


if __name__ == "__main__":
    unittest.main()
