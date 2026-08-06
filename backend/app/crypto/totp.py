"""Time-based one-time passwords (RFC 6238).

Implemented here rather than pulled in as a dependency: it is about thirty lines of
stdlib HMAC, and the deployment target is a small shared box where every installed
package is disk, import time and another thing to keep patched.

SHA-1 is not a mistake. RFC 6238 specifies HMAC-SHA1 and every authenticator app
defaults to it; the security of a TOTP does not rest on collision resistance, and
choosing SHA-256 here would produce codes that Google Authenticator and its peers
silently compute differently.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import secrets
import struct
import time
from urllib.parse import quote

DIGITS = 6
PERIOD_SECONDS = 30

#: How many steps either side of now are accepted. One covers ordinary clock drift and a
#: user who starts typing just before a code rolls over. More than that meaningfully
#: widens the window an intercepted code stays usable in.
SKEW_STEPS = 1

#: 160 bits, the size RFC 4226 recommends for the shared secret.
SECRET_BYTES = 20


def generate_secret() -> str:
    """A fresh base32 secret, in the form authenticator apps expect."""
    return base64.b32encode(secrets.token_bytes(SECRET_BYTES)).decode("ascii").rstrip("=")


def _code_for_counter(secret: str, counter: int) -> str:
    # Re-pad: base32 decoding is strict about it, but the padding is stripped for display
    # and is often stripped again by whatever the user pastes back.
    padded = secret.strip().replace(" ", "").upper()
    padded += "=" * (-len(padded) % 8)
    key = base64.b32decode(padded, casefold=True)
    digest = hmac.new(key, struct.pack(">Q", counter), hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    truncated = struct.unpack(">I", digest[offset : offset + 4])[0] & 0x7FFFFFFF
    return str(truncated % (10**DIGITS)).zfill(DIGITS)


def current_code(secret: str, at: float | None = None) -> str:
    """The code an authenticator would be showing right now. Used by tests."""
    return _code_for_counter(secret, int((at if at is not None else time.time()) // PERIOD_SECONDS))


def verify(secret: str, code: str, at: float | None = None) -> bool:
    """Check a submitted code, allowing one step of clock skew either way."""
    if not secret or not code:
        return False
    cleaned = code.strip().replace(" ", "")
    if not cleaned.isdigit() or len(cleaned) != DIGITS:
        return False

    counter = int((at if at is not None else time.time()) // PERIOD_SECONDS)
    for drift in range(-SKEW_STEPS, SKEW_STEPS + 1):
        try:
            candidate = _code_for_counter(secret, counter + drift)
        except Exception:
            return False
        # Constant time: a comparison that returns early would leak how much of a guess
        # was right, one character at a time.
        if hmac.compare_digest(candidate, cleaned):
            return True
    return False


def provisioning_uri(secret: str, *, username: str, issuer: str = "PRAHARI") -> str:
    """The `otpauth://` URI an authenticator imports, by QR or by paste."""
    label = quote(f"{issuer}:{username}", safe="")
    return (
        f"otpauth://totp/{label}?secret={secret}&issuer={quote(issuer)}"
        f"&algorithm=SHA1&digits={DIGITS}&period={PERIOD_SECONDS}"
    )


def format_for_entry(secret: str) -> str:
    """Grouped into fours, because people type this off a screen by hand."""
    return " ".join(secret[index : index + 4] for index in range(0, len(secret), 4))
