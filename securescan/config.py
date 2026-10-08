"""Central configuration. All values come from environment variables (prefix SECURESCAN_)
or a local .env file. No secrets are hard-coded; API keys are stored as SHA-256 hashes."""
from __future__ import annotations

from functools import lru_cache
from pathlib import Path

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

BASE_DIR = Path(__file__).resolve().parent.parent


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="SECURESCAN_", env_file=".env", extra="ignore")

    # --- Server -------------------------------------------------------------
    host: str = "127.0.0.1"
    port: int = 8000
    session_secret: str = Field(default="", description="Secret used to sign session cookies")
    session_max_age: int = 3600
    https_only_cookies: bool = False  # set True behind TLS

    # --- AuthN / AuthZ: comma-separated SHA-256 hex digests of API keys per role
    viewer_key_hashes: str = ""
    scanner_key_hashes: str = ""
    approver_key_hashes: str = ""
    github_webhook_secret: str = ""

    # --- Scanning -------------------------------------------------------------
    allowed_scan_root: Path = BASE_DIR / "samples"
    allowed_git_hosts: str = "github.com"
    data_dir: Path = BASE_DIR / "data"
    policy_dir: Path = BASE_DIR / "policies"
    tool_timeout_seconds: int = 600
    max_repo_files: int = 50_000
    max_repo_mb: int = 500
    max_concurrent_scans: int = 2
    exclude_dirs: str = ""  # extra comma-separated directory names to skip (e.g. "samples,fixtures")

    # --- Rate limiting --------------------------------------------------------
    rate_limit_per_minute: int = 60
    max_body_bytes: int = 1_000_000

    # --- AI -------------------------------------------------------------------
    ollama_base_url: str = "http://127.0.0.1:11434"
    ollama_model: str = ""  # empty -> chosen dynamically at runtime
    ollama_embed_model: str = ""  # empty -> BM25 keyword retrieval
    llm_max_findings: int = 10  # cap LLM calls per scan (SAST/secret findings)
    llm_timeout_seconds: int = 120

    @field_validator("ollama_base_url")
    @classmethod
    def _ollama_local_only(cls, v: str) -> str:
        # Keep source code on this host: refuse non-local LLM endpoints.
        from urllib.parse import urlparse

        host = urlparse(v).hostname or ""
        if host not in {"127.0.0.1", "localhost", "::1", "ollama"}:
            raise ValueError("ollama_base_url must point to a local Ollama instance")
        return v.rstrip("/")

    @staticmethod
    def _split(v: str) -> set[str]:
        return {x.strip().lower() for x in v.split(",") if x.strip()}

    @property
    def git_hosts(self) -> set[str]:
        return self._split(self.allowed_git_hosts)

    def role_hashes(self) -> dict[str, set[str]]:
        return {
            "viewer": self._split(self.viewer_key_hashes),
            "scanner": self._split(self.scanner_key_hashes),
            "approver": self._split(self.approver_key_hashes),
        }


@lru_cache
def get_settings() -> Settings:
    s = Settings()
    s.data_dir.mkdir(parents=True, exist_ok=True)
    (s.data_dir / "scans").mkdir(exist_ok=True)
    return s
