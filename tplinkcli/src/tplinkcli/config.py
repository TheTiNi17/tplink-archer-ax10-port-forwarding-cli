"""Configuration loading (low → high precedence):

    user config (~/.config/tplink/.env or ~/.tplink.env) < project .env < $TPLINK_ENV < env vars < args

Only three settings matter: the router host, the username (almost always ``admin``),
and the password. Kept out of the code and git via ``.env`` (see ``.env.example``).
The user-config location lets a globally-installed ``tplink`` find credentials from
any directory.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path
from typing import Optional


def _parse_env_file(path: Path) -> dict[str, str]:
    values: dict[str, str] = {}
    if not path.is_file():
        return values
    for raw in path.read_text().splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, val = line.partition("=")
        val = val.strip().strip('"').strip("'")
        values[key.strip()] = val
    return values


def user_config_dir() -> Path:
    """Where a globally-installed tool keeps its config: ``~/.config/tplink``."""
    xdg = os.environ.get("XDG_CONFIG_HOME")
    return (Path(xdg) if xdg else Path.home() / ".config") / "tplink"


def env_file_candidates(
    start: Optional[Path] = None, explicit: Optional[Path] = None
) -> list[Path]:
    """Existing env files in increasing precedence (later entries override earlier ones).

    1. user config (``~/.config/tplink/.env`` or ``~/.tplink.env``) — for a global install
    2. project ``.env`` walking up from the cwd — dev convenience
    3. an explicit path or ``$TPLINK_ENV`` — highest
    """
    found: list[Path] = []
    for candidate in (user_config_dir() / ".env", Path.home() / ".tplink.env"):
        if candidate.is_file():
            found.append(candidate)
            break
    here = (start or Path.cwd()).resolve()
    for directory in (here, *here.parents):
        candidate = directory / ".env"
        if candidate.is_file():
            found.append(candidate)
            break
    override: Optional[Path] = None
    if explicit and explicit.is_file():
        override = explicit
    elif os.environ.get("TPLINK_ENV"):
        override = Path(os.environ["TPLINK_ENV"])
    if override and override.is_file():
        found.append(override)
    return found


@dataclass
class Config:
    host: str
    password: str
    username: str = "admin"
    secure_hash: bool = False

    @classmethod
    def load(
        cls,
        *,
        host: Optional[str] = None,
        username: Optional[str] = None,
        password: Optional[str] = None,
        env_file: Optional[Path] = None,
    ) -> "Config":
        file_vals: dict[str, str] = {}
        for path in env_file_candidates(explicit=env_file):
            file_vals.update(_parse_env_file(path))

        def pick(explicit: Optional[str], *keys: str) -> Optional[str]:
            if explicit:
                return explicit
            for key in keys:
                if os.environ.get(key):
                    return os.environ[key]
            for key in keys:
                if file_vals.get(key):
                    return file_vals[key]
            return None

        resolved_host = pick(host, "ROUTER_IP", "ROUTER_HOST", "TPLINK_HOST")
        resolved_user = pick(username, "ROUTER_USERNAME", "TPLINK_USERNAME") or "admin"
        resolved_pass = pick(password, "ROUTER_PASSWORD", "TPLINK_PASSWORD")
        secure = (pick(None, "ROUTER_SECURE_HASH") or "").lower() in {"1", "true", "yes"}

        missing = [n for n, v in (("host", resolved_host), ("password", resolved_pass)) if not v]
        if missing:
            raise ConfigError(
                f"missing required config: {', '.join(missing)}. Set "
                f"ROUTER_IP/ROUTER_HOST/TPLINK_HOST and ROUTER_PASSWORD/TPLINK_PASSWORD via "
                f"env vars, flags, a project .env, or {user_config_dir() / '.env'} "
                f"(for a global `uv tool install`)."
            )
        assert resolved_host and resolved_pass  # for type-checkers
        return cls(host=resolved_host, password=resolved_pass, username=resolved_user, secure_hash=secure)


class ConfigError(Exception):
    pass
