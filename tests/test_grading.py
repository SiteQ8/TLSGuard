import unittest

from tlsguard.grading import (
    evaluate, has_forward_secrecy, hsts_max_age, is_weak_cipher,
)
from tlsguard.models import CertInfo, HostAudit, ProtocolResult


def proto(**kw):
    return [ProtocolResult(name, status) for name, status in kw.items()]


def make(**overrides):
    a = HostAudit(host="example.com", port=443, reachable=True, trusted=True)
    a.negotiated_version = "TLSv1.3"
    a.negotiated_cipher = "TLS_AES_256_GCM_SHA384"
    a.forward_secrecy = True
    a.protocols = [
        ProtocolResult("SSL 3.0", "untested"),
        ProtocolResult("TLS 1.0", "refused"),
        ProtocolResult("TLS 1.1", "refused"),
        ProtocolResult("TLS 1.2", "supported"),
        ProtocolResult("TLS 1.3", "supported"),
    ]
    a.cert = CertInfo(days_to_expiry=90, hostname_match=True)
    a.hsts = "max-age=63072000"
    for k, v in overrides.items():
        setattr(a, k, v)
    return a


class TestGrading(unittest.TestCase):
    def test_clean_host_is_a_plus(self):
        a = make()
        evaluate(a)
        self.assertEqual(a.grade, "A+")
        self.assertEqual(a.findings, [])

    def test_missing_hsts_caps_at_a(self):
        a = make(hsts=None)
        evaluate(a)
        self.assertEqual(a.grade, "A")

    def test_tls10_caps_at_c(self):
        a = make()
        a.protocols[1] = ProtocolResult("TLS 1.0", "supported")
        evaluate(a)
        self.assertEqual(a.grade, "C")

    def test_untrusted_is_f(self):
        a = make(trusted=False, trust_reason="certificate has expired")
        evaluate(a)
        self.assertEqual(a.grade, "F")

    def test_expiring_soon_caps_at_b(self):
        a = make()
        a.cert = CertInfo(days_to_expiry=10, hostname_match=True)
        evaluate(a)
        self.assertEqual(a.grade, "B")

    def test_no_forward_secrecy_caps_at_b(self):
        a = make(forward_secrecy=False, negotiated_cipher="AES256-SHA")
        evaluate(a)
        self.assertIn(a.grade, ("B", "C"))  # weak cipher may push to C

    def test_unreachable_is_err(self):
        a = HostAudit(host="nope.invalid", reachable=False)
        evaluate(a)
        self.assertEqual(a.grade, "ERR")


class TestCipherHelpers(unittest.TestCase):
    def test_weak_cipher(self):
        self.assertTrue(is_weak_cipher("ECDHE-RSA-RC4-SHA"))
        self.assertTrue(is_weak_cipher("DES-CBC3-SHA"))
        self.assertFalse(is_weak_cipher("TLS_AES_256_GCM_SHA384"))

    def test_forward_secrecy(self):
        self.assertTrue(has_forward_secrecy("TLSv1.3", "TLS_AES_128_GCM_SHA256"))
        self.assertTrue(has_forward_secrecy("TLSv1.2", "ECDHE-RSA-AES128-GCM-SHA256"))
        self.assertFalse(has_forward_secrecy("TLSv1.2", "AES128-GCM-SHA256"))

    def test_hsts_max_age(self):
        self.assertEqual(hsts_max_age("max-age=31536000; includeSubDomains"), 31536000)
        self.assertIsNone(hsts_max_age(None))
        self.assertIsNone(hsts_max_age("includeSubDomains"))


if __name__ == "__main__":
    unittest.main()
