import bcrypt

def hash_password(password: str) -> bytes:
    """Hash a password using bcrypt."""
    salt = bcrypt.gensalt()
    hashed = bcrypt.hashpw(password.encode('utf-8'), salt)
    return hashed

def verify_password(password: str, hashed: bytes) -> bool:
    """Verify a password against a given bcrypt hash."""
    return bcrypt.checkpw(password.encode('utf-8'), hashed)