import os
import sys
from pathlib import Path
from typing import Any, Dict

# Standard library TOML parser for Python 3.11+
if sys.version_info >= (3, 11):
    import tomllib
else:
    try:
        import tomli as tomllib
    except ImportError:
        tomllib = None


class AppSettings:
    """Application configuration and metadata manager."""

    def __init__(self):
        self.version = self._load_version()
        self.environment = os.getenv("APP_ENV", "development")
        self.features = {
            "enable_auto_generate": True,
            "enable_syntax_tips": True,
            "enable_format_normalization": True,
        }

    def _load_version(self) -> str:
        # 1. Environment variable override (ideal for CI/CD)
        if os.getenv("APP_VERSION"):
            return os.getenv("APP_VERSION")

        # 2. Read directly from pyproject.toml
        pyproject_path = Path(__file__).resolve().parent.parent / "pyproject.toml"
        if pyproject_path.exists() and tomllib:
            try:
                with open(pyproject_path, "rb") as f:
                    data = tomllib.load(f)
                    return data.get("project", {}).get("version", "1.0.0")
            except Exception:
                pass

        return "1.0.0"

    def get_public_config(self) -> Dict[str, Any]:
        """Returns parameters exposed to the frontend via API."""
        return {
            "version": f"v{self.version}",
            "environment": self.environment,
            "features": self.features,
        }


settings = AppSettings()