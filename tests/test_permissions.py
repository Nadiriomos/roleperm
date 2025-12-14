import unittest
import os
import tempfile
import roleperm as rp

class TestPermissions(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        self.roles_file = os.path.join(self.tmpdir.name, "roles.json")
        self.perms_file = os.path.join(self.tmpdir.name, "permissions.json")
        rp.add_role("admin", 2, "pw", roles_file=self.roles_file)
        rp.logout()

    def tearDown(self):
        self.tmpdir.cleanup()
        rp.logout()

    def test_role_required_not_logged_in(self):
        @rp.role_required(2)
        def f():
            return 1
        with self.assertRaises(PermissionError):
            f()

    def test_permission_required_default_deny_missing(self):
        role = rp.authenticate("admin", "pw", roles_file=self.roles_file)
        from roleperm.auth import _set_session
        _set_session(role)

        @rp.permission_required("x", permissions_file=self.perms_file, default_allow=False)
        def f():
            return 1

        with self.assertRaises(PermissionError):
            f()

if __name__ == "__main__":
    unittest.main()
