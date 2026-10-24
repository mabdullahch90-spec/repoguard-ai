"""RepoGuard AI — central configuration.

Secrets are loaded from the environment / .env file at runtime and are
NEVER hardcoded in source (OWASP A02:2021 — Cryptographic Failures).
The real `.env` is listed in .gitignore so credentials cannot leak via git.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

from dotenv import load_dotenv

# Load .env from the project root regardless of the current working directory.
load_dotenv(dotenv_path=Path(__file__).resolve().parent.parent / ".env")


def _load_streamlit_secrets() -> None:
    """Merge `.streamlit/secrets.toml` into the process environment.

    Streamlit Community Cloud injects deployment secrets as a TOML file
    instead of a `.env`. Values are only *defaulted* into the environment
    so a real environment variable (or .env entry) always wins.
    Best-effort: any error (no file, old Python without tomllib) is ignored
    and the app simply falls back to offline mode.
    """
    try:
        import tomllib  # Python 3.11+

        secrets_path = Path(__file__).resolve().parent.parent / ".streamlit" / "secrets.toml"
        if not secrets_path.is_file():
            return
        data = tomllib.loads(secrets_path.read_text(encoding="utf-8"))
        for key, value in data.items():
            if isinstance(value, (str, int, float, bool)):
                os.environ.setdefault(str(key), str(value))
    except Exception:  # noqa: BLE001 — configuration must never crash the app
        pass


_load_streamlit_secrets()


def _int_env(name: str, default: int) -> int:
    try:
        return int(os.getenv(name, str(default)))
    except ValueError:
        return default


@dataclass(frozen=True)
class Settings:
    # --- DNotifier (sponsor SDK: realtime + AI pipeline + RAG) -------------
    dnotifier_app_id: str = os.getenv("DNOTIFIER_APP_ID", "")
    dnotifier_secret: str = os.getenv("DNOTIFIER_SECRET", "")
    dnotifier_user_id: str = os.getenv("DNOTIFIER_USER_ID", "svc-repoguard")
    dnotifier_receiver_id: str = os.getenv("DNOTIFIER_RECEIVER_ID", "dev-lead")
    # AI pipeline routing (verified live against the DNotifier API)
    dnotifier_ai_provider: str = os.getenv("DNOTIFIER_AI_PROVIDER", "openai")
    dnotifier_ai_model: str = os.getenv("DNOTIFIER_AI_MODEL", "gpt-4o-mini")

    # --- Optional OpenAI-compatible fallback engine ------------------------
    openai_base_url: str = os.getenv("OPENAI_BASE_URL", "").strip()
    openai_api_key: str = os.getenv("OPENAI_API_KEY", "") or "EMPTY"
    openai_model: str = os.getenv("OPENAI_MODEL", "gpt-4o-mini")

    # --- Guardrails ---------------------------------------------------------
    max_snippet_chars: int = _int_env("MAX_SNIPPET_CHARS", 12_000)
    request_timeout_s: float = float(os.getenv("REQUEST_TIMEOUT_S", "60"))

    @property
    def dnotifier_ready(self) -> bool:
        return bool(self.dnotifier_app_id and self.dnotifier_secret)

    @property
    def openai_ready(self) -> bool:
        return bool(self.openai_base_url) and self.openai_api_key != "EMPTY"


settings = Settings()
