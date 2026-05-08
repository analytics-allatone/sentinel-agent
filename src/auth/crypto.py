from passlib.context import CryptContext

# Use Argon2 (modern, secure, no 72-byte limit)
pwd_context = CryptContext(
    schemes=["argon2"],
    deprecated="auto"
)


def hash_password(password: str) -> str:
    if not password:
        raise ValueError("Password cannot be empty")

    return pwd_context.hash(password)


def verify_password(plain_password: str, hashed_password: str) -> bool:
    if not plain_password or not hashed_password:
        return False

    return pwd_context.verify(plain_password, hashed_password)