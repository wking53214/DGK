import pytest


@pytest.fixture(autouse=True)
def _named_audit_key(monkeypatch):
    """Kernel tests run with a caller-named audit key, as production must."""
    monkeypatch.setenv("DGK_AUDIT_KEY_ID", "test-key")
