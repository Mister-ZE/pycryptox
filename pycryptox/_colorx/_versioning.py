"""
Colorx _versioning:
Internal helpers shared by PURPLE, BLUE and RED for resolving version
specifiers and wrapping/unwrapping the 2-byte version header that every
versioned bundle carries before its base64 encoding.

Not part of the public API. Imported only by the protocol modules in
_colorx. The wire format of a versioned bundle is:

    base64url( [1 byte: major] [1 byte: minor] [protocol payload] )

The `*_VERSIONS` dispatch dicts kept inside each protocol module own the
mapping from "M.m" string to handler. These helpers do not know about
the handlers themselves; they only manipulate the version string and
the version-header bytes.
"""


# Imports:
from typing import Any
import base64
from .._exceptions._exceptions import (
    ArgumentTypeError,
    VersionNotFoundError,
    EncryptionError,
    DecryptionError,
)


# Functions:
def _resolve_version(version: str, versions_dict: dict[str, Any]) -> str:
    """Resolve a version specifier to an exact version string present in
    `versions_dict`.\n
    Accepts:\n
    - Exact version like `"1.0"` -> returned as-is if present.\n
    - Major-only like `"1"` -> returns the latest minor for that major.\n
    Raises `VersionNotFoundError` if no match exists, or
    `ArgumentTypeError` if `version` is not a str."""
    if not isinstance(version, str):
        raise ArgumentTypeError("version", type(version))

    if version in versions_dict:
        return version

    if "." not in version:
        try:
            target_major = int(version)
        except ValueError:
            raise VersionNotFoundError(version)

        candidates: list[tuple[int, int, str]] = []
        for v in versions_dict.keys():
            try:
                major, minor = (int(x) for x in v.split("."))
                if major == target_major:
                    candidates.append((major, minor, v))
            except ValueError:
                continue

        if not candidates:
            raise VersionNotFoundError(version)

        _, _, best = max(candidates, key=lambda t: (t[0], t[1]))
        return best

    raise VersionNotFoundError(version)


def _matches_specifier(bundle_version: str, specifier: str) -> bool:
    """Return True if `bundle_version` (an exact `"M.m"` string) is
    acceptable under the caller's `specifier` (which may be exact or
    major-only)."""
    if "." in specifier:
        return bundle_version == specifier
    try:
        target_major = int(specifier)
        bundle_major = int(bundle_version.split(".")[0])
    except (ValueError, IndexError):
        return False
    return bundle_major == target_major


def _wrap_version_bytes(actual_version: str, inner_b64: str) -> str:
    """Prepend the 2-byte version header (major, minor) to a base64url
    inner payload and return the new base64url string.

    `actual_version` must be an exact `"M.m"` string with both fields in
    0-255. Raises `EncryptionError` if it is not, or if `inner_b64` is
    not valid base64url."""
    try:
        major, minor = (int(x) for x in actual_version.split("."))
        if not (0 <= major <= 255 and 0 <= minor <= 255):
            raise ValueError()
    except ValueError:
        raise EncryptionError(f"invalid version format: {actual_version}")
    try:
        inner = base64.urlsafe_b64decode(inner_b64)
    except Exception:
        raise EncryptionError("inner payload is not valid base64")
    return base64.urlsafe_b64encode(bytes([major, minor]) + inner).decode()


def _unwrap_version_bytes(msg: str, version_specifier: str) -> tuple[str, str]:
    """Decode the base64url `msg`, extract the 2-byte version header,
    verify that the embedded version matches `version_specifier`, and
    return `(bundle_version, inner_b64)` where `inner_b64` is the
    base64url-encoded payload after the header.

    Raises `DecryptionError` if the input is not valid base64, is too
    short to carry a header, or carries a version that does not match
    `version_specifier`."""
    try:
        versioned = base64.urlsafe_b64decode(msg)
    except Exception:
        raise DecryptionError("message is not valid base64")
    if len(versioned) < 2:
        raise DecryptionError("message too short for version header")
    bundle_version = f"{versioned[0]}.{versioned[1]}"
    if not _matches_specifier(bundle_version, version_specifier):
        raise DecryptionError(
            f"version mismatch: bundle is v{bundle_version}, "
            f"caller requested v{version_specifier}"
        )
    inner_b64 = base64.urlsafe_b64encode(versioned[2:]).decode()
    return bundle_version, inner_b64


def _extract_version(msg: str) -> str:
    """Extract the protocol version from a bundle without decrypting it.\n
    Useful for routing or migration logic.\n
    Raises `ArgumentTypeError` if `msg` is not a str, or `DecryptionError`
    if the bundle is malformed."""
    if not isinstance(msg, str):
        raise ArgumentTypeError("msg", type(msg))
    try:
        versioned = base64.urlsafe_b64decode(msg)
    except Exception:
        raise DecryptionError("message is not valid base64")
    if len(versioned) < 2:
        raise DecryptionError("message too short for version header")
    return f"{versioned[0]}.{versioned[1]}"
