import os, sys
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'src')))

import unittest
from roleperm.utils import hash_password, verify_password, PasswordHash


class TestUtils(unittest.TestCase):
    def test_hash_and_verify(self):
        ph = hash_password("secret123", iterations=100_000)
        self.assertTrue(verify_password("secret123", ph))
        self.assertFalse(verify_password("wrong", ph))

    def test_kdf_mismatch(self):
        ph = hash_password("secret123", iterations=100_000)
        bad = PasswordHash(kdf="unknown", iterations=ph.iterations, salt_hex=ph.salt_hex, hash_hex=ph.hash_hex)
        with self.assertRaises(ValueError):
            verify_password("secret123", bad)


if __name__ == "__main__":
    unittest.main()
