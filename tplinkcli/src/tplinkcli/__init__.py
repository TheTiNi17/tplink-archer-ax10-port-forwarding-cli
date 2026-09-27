"""tplinkcli — a CLI/MCP tool for TP-Link Archer/AX routers via their encrypted web API."""

from .client import AuthError, TplinkClient, TplinkError
from .config import Config, ConfigError
from .crypto import AesCipher, RsaCipher, TpEncryptor

__all__ = [
    "TplinkClient",
    "TplinkError",
    "AuthError",
    "Config",
    "ConfigError",
    "TpEncryptor",
    "AesCipher",
    "RsaCipher",
]

__version__ = "0.1.0"
