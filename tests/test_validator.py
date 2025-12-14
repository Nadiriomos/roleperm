import unittest
from roleperm.validators import (
    validate_roles_data, validate_permissions_data,
    RolesValidationError, PermissionsValidationError
)

class TestValidators(unittest.TestCase):
    def test_roles_ok(self):
        raw = [{
            "name": "admin",
            "id": 2,
            "kdf": "pbkdf2_sha256",
            "iterations": 50000,
            "salt": "aa"*16,
            "password_hash": "bb"*32
        }]
        validate_roles_data(raw)

    def test_roles_dup_id(self):
        raw = [
            {"name":"a","id":1,"kdf":"pbkdf2_sha256","iterations":50000,"salt":"aa"*16,"password_hash":"bb"*32},
            {"name":"b","id":1,"kdf":"pbkdf2_sha256","iterations":50000,"salt":"aa"*16,"password_hash":"bb"*32},
        ]
        with self.assertRaises(RolesValidationError):
            validate_roles_data(raw)

    def test_permissions_ok(self):
        raw = {"schema_version":1,"permissions":{"view":{"label":"View","allowed_role_ids":[1,2]}}}
        validate_permissions_data(raw)

    def test_permissions_bad_allowed(self):
        raw = {"schema_version":1,"permissions":{"view":{"allowed_role_ids":["x"]}}}
        with self.assertRaises(PermissionsValidationError):
            validate_permissions_data(raw)

if __name__ == "__main__":
    unittest.main()
