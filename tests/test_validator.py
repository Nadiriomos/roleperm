import json
import os
import tempfile
import unittest

import roleperm as rp


class TestValidator(unittest.TestCase):
    def _write(self, obj):
        fd, path = tempfile.mkstemp(suffix=".json")
        os.close(fd)
        with open(path, "w", encoding="utf-8") as f:
            json.dump(obj, f)
        return path

    def test_valid_file_passes(self):
        path = self._write([
            {
                "name": "admin",
                "id": 2,
                "kdf": "pbkdf2_sha256",
                "iterations": 200000,
                "salt": "a1" * 16,
                "password_hash": "b2" * 32,
            }
        ])
        rp.validate_roles_file(path)
        os.remove(path)

    def test_duplicate_ids_fails(self):
        path = self._write([
            {"name": "a", "id": 1, "salt": "aa", "password_hash": "bb"},
            {"name": "b", "id": 1, "salt": "aa", "password_hash": "bb"},
        ])
        with self.assertRaises(rp.RolesValidationError) as ctx:
            rp.validate_roles_file(path)
        self.assertIn("duplicate role id", str(ctx.exception).lower())
        os.remove(path)

    def test_bad_root_fails(self):
        path = self._write({"name": "admin"})
        with self.assertRaises(rp.RolesValidationError):
            rp.validate_roles_file(path)
        os.remove(path)
