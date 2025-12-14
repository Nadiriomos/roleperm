import unittest, tempfile, os
import roleperm as rp

class TestConfigLogin(unittest.TestCase):
    def test_login_none_when_no_roles(self):
        with tempfile.TemporaryDirectory() as td:
            rp.configure(base_dir=td)
            self.assertIsNone(rp.login(title="x"))

    def test_paths_folder(self):
        with tempfile.TemporaryDirectory() as td:
            p = rp.configure(base_dir=td)
            expected_suffix = os.path.join("roleperm", "roles.json")
            self.assertTrue(os.path.normpath(p.roles_file).endswith(os.path.normpath(expected_suffix)))

if __name__=="__main__":
    unittest.main()
