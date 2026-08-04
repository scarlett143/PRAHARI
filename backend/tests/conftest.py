import os
from pathlib import Path

TEST_DB = Path("/tmp/prahari_test.db")
if TEST_DB.exists():
    TEST_DB.unlink()

os.environ["ENVIRONMENT"] = "test"
os.environ["DATABASE_URL"] = f"sqlite+aiosqlite:///{TEST_DB}"
os.environ["JWT_SECRET"] = "test-only-jwt-secret-that-is-long-enough-and-not-for-production"
os.environ["PQC_BACKEND"] = "kyber-py"
os.environ["REKEY_AFTER_MESSAGES"] = "100"
os.environ["REKEY_AFTER_MINUTES"] = "15"
