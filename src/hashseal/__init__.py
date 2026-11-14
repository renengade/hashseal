"""hashseal: SHA-256 + Ed25519 file integrity and provenance."""

from importlib.metadata import PackageNotFoundError
from importlib.metadata import version as _version

try:
    __version__ = _version("hashseal")
except PackageNotFoundError:  # running from a source tree without installation
    __version__ = "0.0.0"

from .cli import main
from .core import DEFAULT_TSA, FORMAT, MANIFEST_NAME, sha256_file
from .core import fmt_time as _fmt_gen_time
from .tsa import (
    FREETSA_CA_PEM,
    FREETSA_CA_SHA256,
    TimestampError,
    _post,
    check_token,
    token_metadata,
)

__all__ = [
    "DEFAULT_TSA",
    "FORMAT",
    "FREETSA_CA_PEM",
    "FREETSA_CA_SHA256",
    "MANIFEST_NAME",
    "TimestampError",
    "__version__",
    "_fmt_gen_time",
    "_post",
    "check_token",
    "main",
    "sha256_file",
    "token_metadata",
]
