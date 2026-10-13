"""RFC 6238 TOTP with replay protection (a time-step can only be used once)."""

from __future__ import annotations

import time

import pyotp

ISSUER = "AEGIS"
_INTERVAL = 30
_VALID_WINDOW = 1  # accept the previous/next step to tolerate clock drift


def new_secret() -> str:
    return pyotp.random_base32(length=32)


def provisioning_uri(secret: str, account: str) -> str:
    return pyotp.TOTP(secret, interval=_INTERVAL).provisioning_uri(name=account, issuer_name=ISSUER)


def verify(
    secret: str, code: str, last_used_step: int | None, now: float | None = None
) -> int | None:
    """Return the matched time-step if ``code`` is valid and not replayed, else ``None``."""
    code = code.strip().replace(" ", "")
    if not code.isdigit() or len(code) != 6:
        return None
    totp = pyotp.TOTP(secret, interval=_INTERVAL)
    current = now if now is not None else time.time()
    current_step = int(current // _INTERVAL)
    for offset in range(-_VALID_WINDOW, _VALID_WINDOW + 1):
        step = current_step + offset
        if last_used_step is not None and step <= last_used_step:
            continue
        if pyotp.utils.strings_equal(totp.at(step * _INTERVAL), code):
            return step
    return None
