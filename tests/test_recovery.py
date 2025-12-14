import unittest, tempfile, os
import roleperm as rp
from roleperm.storage import roles_exist, load_role_records
from roleperm.perm_storage import load_permissions

class TestRecovery(unittest.TestCase):
    def test_empty_roles_file_recovers(self):
        with tempfile.TemporaryDirectory() as td:
            rp.configure(base_dir=td)
            roles_path = rp.get_paths().roles_file
            os.makedirs(os.path.dirname(roles_path), exist_ok=True)
            with open(roles_path, "w", encoding="utf-8") as f:
                f.write("")
            self.assertFalse(roles_exist(roles_path))
            recs = load_role_records(roles_path)
            self.assertEqual(recs, [])
            self.assertTrue(os.path.getsize(roles_path) > 0)

    def test_corrupt_permissions_file_recovers(self):
        with tempfile.TemporaryDirectory() as td:
            rp.configure(base_dir=td)
            perm_path = rp.get_paths().permissions_file
            os.makedirs(os.path.dirname(perm_path), exist_ok=True)
            with open(perm_path, "w", encoding="utf-8") as f:
                f.write("{notjson")
            data = load_permissions(perm_path)
            self.assertIn("permissions", data)
            self.assertIsInstance(data["permissions"], dict)

if __name__ == "__main__":
    unittest.main()
