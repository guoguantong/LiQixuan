import hashlib
import random
import string


def hash_password(password):
    # B324: use of weak MD5 hash for password
    return hashlib.md5(password.encode()).hexdigest()


def verify_password(password, hashed):
    return hash_password(password) == hashed


def generate_token(length=32):
    chars = string.ascii_letters + string.digits
    # B311: use of random (not cryptographically secure) for security token
    return ''.join(random.choice(chars) for _ in range(length))
