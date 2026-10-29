import os
import json
from pathlib import Path
from typing import Any, Optional, Dict, Union
from urllib.parse import urlparse


def is_safe_path(target_path: Union[str, Path], base_dir: Union[str, Path]) -> bool:
    """
    Check if target_path resolves within base_dir to prevent path injection / directory traversal.
    """
    try:
        base = os.path.abspath(os.path.realpath(str(base_dir)))
        target = os.path.abspath(os.path.realpath(str(target_path)))
        if os.path.commonpath([base, target]) != base:
            return False
        return Path(target).is_relative_to(Path(base))
    except Exception:
        return False


def is_safe_url(target_url: str, allowed_hosts: Optional[set] = None) -> bool:
    """
    Check if target_url is safe for redirection (prevents Open Redirect).
    Accepts only local relative paths (e.g., starting with '/' but not '//' or '\\')
    or URLs whose netloc is explicitly allowed.
    """
    if not target_url or not isinstance(target_url, str):
        return False

    # Strip whitespace and control characters
    target_url = target_url.strip()

    # Reject scheme-relative URLs like '//evil.com' or backslash URLs like '/\evil.com'
    if target_url.startswith("//") or target_url.startswith("/\\") or target_url.startswith("\\"):
        return False

    parsed = urlparse(target_url)

    # If target has a scheme or netloc, ensure it's in allowed_hosts
    if parsed.scheme or parsed.netloc:
        if not allowed_hosts:
            return False
        return parsed.netloc in allowed_hosts

    # Pure relative paths starting with / are allowed
    return target_url.startswith("/")


# ------------------------------------------------------------
# ---------------------- File Manager ---------------------
# ------------------------------------------------------------


class FileManager:
    """Handles file I/O operations."""

    @staticmethod
    def _validate_path(
        filepath: Union[str, Path], base_dir: Optional[Union[str, Path]] = None
    ) -> Path:
        """Sanitize and validate file path against path traversal if base_dir is specified."""
        path_obj = Path(filepath).resolve()
        if base_dir is not None:
            if not is_safe_path(path_obj, base_dir):
                raise ValueError(f"Unsafe path detected: {filepath}")
        return path_obj

    @staticmethod
    def ensure_directory(path: str, base_dir: Optional[Union[str, Path]] = None) -> None:
        """Create directory if it doesn't exist."""
        path_obj = FileManager._validate_path(path, base_dir)
        os.makedirs(path_obj, exist_ok=True)

    @staticmethod
    def save_json(data: Any, filepath: str, base_dir: Optional[Union[str, Path]] = None) -> None:
        """Save data as JSON to file."""
        path_obj = FileManager._validate_path(filepath, base_dir)
        with open(path_obj, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=4, ensure_ascii=False)

    @staticmethod
    def load_json(
        filepath: Union[str, Path], base_dir: Optional[Union[str, Path]] = None
    ) -> Optional[Dict[str, Any]]:
        """Load JSON from file, return None if file doesn't exist."""
        path_obj = FileManager._validate_path(filepath, base_dir)
        if not path_obj.exists():
            return None

        with open(path_obj, "r", encoding="utf-8") as f:
            return json.load(f)

    @staticmethod
    def save_text(content: str, filepath: str, base_dir: Optional[Union[str, Path]] = None) -> None:
        """Save text content to file."""
        path_obj = FileManager._validate_path(filepath, base_dir)
        with open(path_obj, "w", encoding="utf-8") as f:
            f.write(content)

    @staticmethod
    def load_text(filepath: Union[str, Path], base_dir: Optional[Union[str, Path]] = None) -> str:
        """Load text content from file."""
        path_obj = FileManager._validate_path(filepath, base_dir)
        with open(path_obj, "r", encoding="utf-8") as f:
            return f.read()


file_manager = FileManager()
