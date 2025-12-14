from __future__ import annotations
import hashlib, hmac, secrets
DEFAULT_ITERATIONS=200_000
MIN_ITERATIONS=50_000
def generate_salt_hex(nbytes:int=16)->str:
    return secrets.token_hex(nbytes)
def pbkdf2_sha256(password:str,salt_hex:str,iterations:int=DEFAULT_ITERATIONS)->str:
    if not isinstance(password,str) or password=="":
        raise ValueError("Password must be a non-empty string.")
    if not isinstance(salt_hex,str) or salt_hex=="":
        raise ValueError("salt_hex must be a non-empty string.")
    if not isinstance(iterations,int) or iterations<MIN_ITERATIONS:
        raise ValueError(f"iterations must be int >= {MIN_ITERATIONS}.")
    salt=bytes.fromhex(salt_hex)
    dk=hashlib.pbkdf2_hmac("sha256",password.encode("utf-8"),salt,iterations)
    return dk.hex()
def verify_pbkdf2_sha256(password:str,salt_hex:str,expected_hash_hex:str,iterations:int)->bool:
    return hmac.compare_digest(pbkdf2_sha256(password,salt_hex,iterations),expected_hash_hex)
def is_hex(s:str)->bool:
    if not isinstance(s,str) or s=="":
        return False
    try:
        bytes.fromhex(s); return True
    except ValueError:
        return False
