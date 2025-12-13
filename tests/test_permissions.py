import os, sys
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'src')))

import unittest
import roleperm as rp


class TestPermissions(unittest.TestCase):
    def setUp(self):
        rp.logout()

    def test_requires_login(self):
        @rp.role_required(1)
        def foo():
            return 1

        with self.assertRaises(PermissionError):
            foo()

    def test_requires_role_id(self):
        # create a fake session by authenticating from in-memory roles file is hard here;
        # we'll directly set a session through private helper by logging in headlessly.
        # We'll create roles in a temp file.
        import tempfile, os

        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "roles.json")
            rp.add_role("admin", 2, "pw", roles_file=path)
            role = rp.authenticate("admin", "pw", roles_file=path)
            # set session via login API is UI; we simulate by calling internal _set_session
            from roleperm.auth import _set_session
            _set_session(role)

            @rp.role_required(2)
            def ok():
                return "ok"

            @rp.role_required(1)
            def no():
                return "no"

            self.assertEqual(ok(), "ok")
            with self.assertRaises(PermissionError):
                no()


if __name__ == "__main__":
    unittest.main()
