"""
Colorx YELLOW:
The YELLOW protocol is used for data steganography,
meaning it aims to conceal data within innocuous
documents. It is recommended for masking encrypted
data before transmission over monitored networks.
WARNING: This version isn't useful yet. An improvement
is planned for the next Pycryptox update.
"""


# Imports:
from typing import Any
from .._exceptions._exceptions import *


# Functions:
# -- Versions: --
# -- v0.0: --
def _stegav0_0() -> str:
    return "Actually... there's nothing I can return."

def _unstegav0_0() -> str:
    return "Actually... there's nothing I can return."


# -- Main functions --
__all__ = [
    "stega",
    "unstega"
]

def stega(version: str, *args: Any, **kwargs: Any) -> str:
    """**Latest version (v0.0):**
    ```python
        def stega(
            version: str
        ) -> str
    ```
    This version isn't useful yet. An improvement is planned for the next
    Pycryptox update."""
    handler = _STEGA_VERSIONS.get(version)

    if not handler:
        raise VersionNotFoundError(version)
    
    return handler(*args, **kwargs)

def unstega(version: str, *args: Any, **kwargs: Any) -> str:
    """**Latest version (v0.0):**
    ```python
        def unstega(
            version: str
        ) -> str
    ```
    This version isn't useful yet. An improvement is planned for the next
    Pycryptox update."""
    handler = _UNSTEGA_VERSIONS.get(version)

    if not handler:
        raise VersionNotFoundError(version)
    
    return handler(*args, **kwargs)


# Constants:
_STEGA_VERSIONS = {
    "0.0": _stegav0_0,
}

_UNSTEGA_VERSIONS = {
    "0.0": _unstegav0_0,
}