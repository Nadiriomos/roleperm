import unittest
from roleperm.utils import generate_salt_hex, pbkdf2_sha256, verify_pbkdf2_sha256, MIN_ITERATIONS

class TestUtils(unittest.TestCase):
    def test_hash_and_verify(self):
        salt = generate_salt_hex()
        h = pbkdf2_sha256("pw", salt, MIN_ITERATIONS)
        self.assertTrue(verify_pbkdf2_sha256("pw", salt, h, MIN_ITERATIONS))
        self.assertFalse(verify_pbkdf2_sha256("nope", salt, h, MIN_ITERATIONS))

if __name__ == "__main__":
    unittest.main()
