import os
from codewiki.src.utils import is_safe_path, is_safe_url
from codewiki.src.be.cluster_modules import mask_secret, redact_text


def test_is_safe_path():
    base = os.path.abspath("/tmp/base_docs")
    safe_target = os.path.abspath("/tmp/base_docs/overview.md")
    unsafe_target = os.path.abspath("/tmp/base_docs/../etc/passwd")

    assert is_safe_path(safe_target, base) is True
    assert is_safe_path(unsafe_target, base) is False


def test_is_safe_url():
    assert is_safe_url("/static-docs/job123/") is True
    assert is_safe_url("//evil.com") is False
    assert is_safe_url("https://evil.com") is False


def test_mask_secret():
    assert mask_secret("") == ""
    assert mask_secret("short") == "***"
    assert mask_secret("secret_token_12345") == "sec***345"
    assert redact_text("secret_token_12345") == "sec***345"
