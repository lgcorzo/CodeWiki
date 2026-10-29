import os
from codewiki.src.utils import is_safe_path, is_safe_url


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


def test_file_manager_path_validation(tmp_path):
    from codewiki.src.utils import FileManager

    base_dir = tmp_path / "safe_dir"
    base_dir.mkdir()
    safe_file = base_dir / "test.txt"
    safe_file.write_text("hello")

    assert FileManager.load_text(safe_file, base_dir=base_dir) == "hello"

    unsafe_file = tmp_path / "outside.txt"
    unsafe_file.write_text("secret")

    import pytest

    with pytest.raises(ValueError, match="Unsafe path detected"):
        FileManager.load_text(unsafe_file, base_dir=base_dir)
