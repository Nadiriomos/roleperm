import unittest, tempfile
import roleperm as rp
from roleperm.auth import _set_session

class TestPermissions(unittest.TestCase):
    def setUp(self):
        self.td=tempfile.TemporaryDirectory()
        rp.configure(base_dir=self.td.name)
        rp.add_role("admin",2,"pw")
        rp.logout()
    def tearDown(self):
        self.td.cleanup()
        rp.logout()
    def test_default_deny_missing_key(self):
        role=rp.authenticate("admin","pw")
        _set_session(role)
        @rp.permission_required("x", default_allow=False)
        def f(): return 1
        with self.assertRaises(PermissionError):
            f()
    def test_manage_key_registered(self):
        self.assertIn(rp.MANAGE_PERMISSION_KEY, rp.list_registered_permissions())
if __name__=="__main__":
    unittest.main()
