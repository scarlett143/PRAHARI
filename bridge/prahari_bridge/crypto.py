"""Single import point for the audited PRAHARI primitives.

The bridge deliberately does **not** reimplement the handshake or the AEAD. It reuses the
exact modules the backend and its test suite exercise, so an aircraft cannot drift away
from the protocol the rest of the platform speaks. Only these primitives are pulled in --
no database, no API, no server-side code runs on the aircraft.

Resolution order:
  1. ``app.crypto`` already importable (installed, or running inside the backend image)
  2. ``PRAHARI_BACKEND_PATH`` environment variable
  3. ``../backend`` relative to this checkout
"""
from __future__ import annotations

import os
import sys
from pathlib import Path


def _ensure_backend_importable() -> None:
    try:
        import app.crypto  # noqa: F401
    except ImportError:
        pass
    else:
        return

    candidates = []
    configured = os.getenv("PRAHARI_BACKEND_PATH")
    if configured:
        candidates.append(Path(configured))
    candidates.append(Path(__file__).resolve().parents[2] / "backend")

    for candidate in candidates:
        if (candidate / "app" / "crypto" / "__init__.py").is_file():
            sys.path.insert(0, str(candidate))
            return

    raise ImportError(
        "cannot locate the PRAHARI backend package. Set PRAHARI_BACKEND_PATH to the "
        "directory containing app/, or run the bridge from inside the repository."
    )


_ensure_backend_importable()

from app.crypto import aead, hybrid, identity, pqc, ratchet  # noqa: E402

__all__ = ["aead", "hybrid", "identity", "pqc", "ratchet"]
