import base64
import hashlib
import re
import secrets
from datetime import timedelta

import bcrypt
import jwt

from app.core.config import get_settings
from app.database.session import utcnow

ALGORITHM = "HS256"
BCRYPT_ROUNDS = 12


def _prehash(password: str) -> bytes:
    # bcrypt only uses the first 72 bytes; pre-hashing keeps long passphrases fully significant.
    return base64.b64encode(hashlib.sha256(password.encode("utf-8")).digest())


def hash_password(password: str) -> str:
    return bcrypt.hashpw(_prehash(password), bcrypt.gensalt(rounds=BCRYPT_ROUNDS)).decode()


def verify_password(password: str, password_hash: str) -> bool:
    try:
        return bcrypt.checkpw(_prehash(password), password_hash.encode())
    except ValueError:
        return False


_DUMMY_HASH = None


def dummy_verify() -> None:
    """Spend comparable time when the account does not exist (limits user enumeration by timing)."""
    global _DUMMY_HASH
    if _DUMMY_HASH is None:
        _DUMMY_HASH = hash_password(secrets.token_hex(8))
    verify_password("not-the-password", _DUMMY_HASH)


PASSWORD_RULES = (
    (re.compile(r".{10,}"), "at least 10 characters"),
    (re.compile(r"[A-Za-z]"), "a letter"),
    (re.compile(r"\d"), "a digit"),
)


def password_problems(password: str) -> list[str]:
    problems = [msg for rx, msg in PASSWORD_RULES if not rx.search(password)]
    if len(password) > 256:
        problems.append("at most 256 characters")
    return problems


def create_access_token(user_id: int) -> tuple[str, str, int]:
    settings = get_settings()
    jti = secrets.token_hex(16)
    expires_in = settings.access_token_expire_minutes * 60
    now = utcnow()
    payload = {
        "sub": str(user_id),
        "jti": jti,
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(seconds=expires_in)).timestamp()),
        "iss": "sentinelx",
    }
    return jwt.encode(payload, settings.secret_key, algorithm=ALGORITHM), jti, expires_in


def decode_access_token(token: str) -> dict | None:
    try:
        return jwt.decode(
            token,
            get_settings().secret_key,
            algorithms=[ALGORITHM],
            issuer="sentinelx",
            options={"require": ["exp", "sub", "jti"]},
        )
    except jwt.PyJWTError:
        return None
