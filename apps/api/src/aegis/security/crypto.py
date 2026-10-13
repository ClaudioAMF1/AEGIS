"""Password hashing, token generation and at-rest encryption helpers."""

from __future__ import annotations

import base64
import hashlib
import hmac
import secrets

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError
from cryptography.fernet import Fernet, InvalidToken

from aegis.config import get_settings

_hasher = PasswordHasher()  # argon2id with library defaults (RFC 9106 low-memory profile)

# Used to equalise response time when the user does not exist.
_DUMMY_HASH = _hasher.hash(secrets.token_urlsafe(16))

MIN_PASSWORD_LENGTH = 12


def hash_password(password: str) -> str:
    return _hasher.hash(password)


def verify_password(password_hash: str | None, password: str) -> bool:
    try:
        return _hasher.verify(password_hash or _DUMMY_HASH, password) and password_hash is not None
    except (VerifyMismatchError, VerificationError, InvalidHashError):
        return False


def needs_rehash(password_hash: str) -> bool:
    return _hasher.check_needs_rehash(password_hash)


def password_problems(password: str, email: str | None = None) -> list[str]:
    """Length-based policy (OWASP ASVS 2.1): no composition rules, block trivial choices."""
    problems: list[str] = []
    if len(password) < MIN_PASSWORD_LENGTH:
        problems.append(f"must contain at least {MIN_PASSWORD_LENGTH} characters")
    if len(password) > 128:
        problems.append("must contain at most 128 characters")
    if len(set(password)) < 5:
        problems.append("is too repetitive")
    local = email.split("@")[0].lower() if email else ""
    if len(local) >= 3 and local in password.lower():
        problems.append("must not contain the e-mail name")
    return problems


def new_token(prefix: str = "") -> str:
    return prefix + secrets.token_urlsafe(32)


def hash_token(token: str) -> str:
    """Tokens are high-entropy, so a keyed SHA-256 is sufficient (and fast for lookups)."""
    key = get_settings().secret_key.get_secret_value().encode()
    return hmac.new(key, token.encode(), hashlib.sha256).hexdigest()


def constant_time_equals(a: str, b: str) -> bool:
    return hmac.compare_digest(a.encode(), b.encode())


def _fernet() -> Fernet:
    secret = get_settings().secret_key.get_secret_value().encode()
    derived = hashlib.sha256(b"aegis-field-encryption:" + secret).digest()
    return Fernet(base64.urlsafe_b64encode(derived))


def encrypt_field(value: str) -> str:
    return _fernet().encrypt(value.encode()).decode()


def decrypt_field(value: str) -> str | None:
    try:
        return _fernet().decrypt(value.encode()).decode()
    except InvalidToken:
        return None


# Lab and corporate deployments often use internal domains (.lab, .internal, .local) that
# strict validators reject, so only the basic shape is enforced.
EMAIL_PATTERN = r"^[^@\s]{1,64}@[A-Za-z0-9.-]{1,253}$"
