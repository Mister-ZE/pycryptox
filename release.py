#!/usr/bin/env python
"""
release.py - Automated release for pycryptox.

Run from the project root:
    python release.py

Flow:
    1. Check that the git working tree is clean.
    2. Read the current version from pyproject.toml.
    3. Ask interactively for the new version (patch / minor / major / custom).
    4. Ask for release notes (multi-line, end with a single line "END").
    5. Show a summary and ask to proceed.
    6. Run the test suite (aborts if any test fails).
    7. Bump the version in pyproject.toml and pycryptox/__init__.py.
    8. Commit the version bump.
    9. Tag the commit (v<version>) and push to the remote.
   10. Build the package (sdist + wheel) via `python -m build`.
   11. Upload to PyPI via `python -m twine upload`.
   12. Create a GitHub release with the notes via `gh release create`.

Prerequisites (one-time setup):
    pip install build twine
    Configure ~/.pypirc with your PyPI token
    Install GitHub CLI and run: gh auth login

If any step fails, the script aborts immediately. Manual cleanup may be
needed (e.g. revert the version bump commit if PyPI upload failed).
"""

from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path


# ---------------------------------------------------------------------------
# Config - adjust paths if your layout differs
# ---------------------------------------------------------------------------

PROJECT_ROOT = Path(__file__).resolve().parent
PYPROJECT = PROJECT_ROOT / "pyproject.toml"
PACKAGE_INIT = PROJECT_ROOT / "pycryptox" / "__init__.py"
TESTS_RUNNER = PROJECT_ROOT / "pycryptox" / "tests" / "run_all.py"
DEFAULT_BRANCH = "main"   # change to "master" if your repo uses that


# ---------------------------------------------------------------------------
# Pretty output helpers
# ---------------------------------------------------------------------------

def header(msg: str) -> None:
    print(f"\n{'=' * 60}\n  {msg}\n{'=' * 60}")

def step(msg: str) -> None:
    print(f"\n--- {msg} ---")

def info(msg: str) -> None:
    print(f"  {msg}")

def abort(msg: str) -> None:
    print(f"\nABORTED: {msg}")
    sys.exit(1)


# ---------------------------------------------------------------------------
# Process runner
# ---------------------------------------------------------------------------

def run(cmd: str, check: bool = True, capture: bool = False) -> subprocess.CompletedProcess:
    """Run a shell command in PROJECT_ROOT. Aborts on non-zero exit if check=True."""
    print(f"  $ {cmd}")
    result = subprocess.run(
        cmd,
        shell=True,
        cwd=str(PROJECT_ROOT),
        capture_output=capture,
        text=True,
    )
    if check and result.returncode != 0:
        if capture and result.stderr:
            print(result.stderr)
        abort(f"Command failed (exit {result.returncode}): {cmd}")
    return result


# ---------------------------------------------------------------------------
# Version reading + writing
# ---------------------------------------------------------------------------

VERSION_RE_TOML = re.compile(r'^(version\s*=\s*)"([^"]+)"', re.MULTILINE)
VERSION_RE_INIT = re.compile(r'^(__version__\s*=\s*)"([^"]+)"', re.MULTILINE)


def read_version() -> str:
    if not PYPROJECT.exists():
        abort(f"pyproject.toml not found at {PYPROJECT}")
    text = PYPROJECT.read_text(encoding="utf-8")
    m = VERSION_RE_TOML.search(text)
    if not m:
        abort("Could not parse 'version = \"...\"' in pyproject.toml")
    return m.group(2)


def write_version(new_version: str) -> None:
    # pyproject.toml
    text = PYPROJECT.read_text(encoding="utf-8")
    new_text, n = VERSION_RE_TOML.subn(rf'\1"{new_version}"', text, count=1)
    if n == 0:
        abort("Failed to update version in pyproject.toml")
    PYPROJECT.write_text(new_text, encoding="utf-8")
    info(f"pyproject.toml: version -> {new_version}")

    # pycryptox/__init__.py - only if it has __version__
    if PACKAGE_INIT.exists():
        text = PACKAGE_INIT.read_text(encoding="utf-8")
        new_text, n = VERSION_RE_INIT.subn(rf'\1"{new_version}"', text, count=1)
        if n > 0:
            PACKAGE_INIT.write_text(new_text, encoding="utf-8")
            info(f"pycryptox/__init__.py: __version__ -> {new_version}")
        else:
            info("pycryptox/__init__.py has no __version__ (skipped)")


# ---------------------------------------------------------------------------
# Interactive prompts
# ---------------------------------------------------------------------------

def bump(parts: list[int], level: str) -> list[int]:
    """level in {'patch', 'minor', 'major'}"""
    while len(parts) < 3:
        parts.append(0)
    if level == "patch":
        parts[2] += 1
    elif level == "minor":
        parts[1] += 1
        parts[2] = 0
    elif level == "major":
        parts[0] += 1
        parts[1] = 0
        parts[2] = 0
    return parts


def ask_new_version(current: str) -> str:
    print(f"\n  Current version: {current}")
    try:
        parts = list(map(int, current.split(".")))
    except ValueError:
        parts = [0, 0, 0]
    while len(parts) < 3:
        parts.append(0)

    next_patch = ".".join(map(str, bump(parts.copy(), "patch")))
    next_minor = ".".join(map(str, bump(parts.copy(), "minor")))
    next_major = ".".join(map(str, bump(parts.copy(), "major")))

    print(f"    1) Patch  -> {next_patch}")
    print(f"    2) Minor  -> {next_minor}")
    print(f"    3) Major  -> {next_major}")
    print(f"    4) Custom")
    choice = input("  Choice [1-4]: ").strip()

    if choice == "1":
        return next_patch
    if choice == "2":
        return next_minor
    if choice == "3":
        return next_major
    if choice == "4":
        v = input("  New version (e.g. 1.2.3): ").strip()
        if not re.fullmatch(r"\d+\.\d+\.\d+", v):
            abort(f"Invalid version format: {v}")
        return v
    abort(f"Invalid choice: {choice}")


def ask_release_notes(new_version: str) -> str:
    print(f"\n  Release notes for v{new_version}")
    print("  Type your notes line by line, then a line with only 'END':")
    lines = []
    while True:
        try:
            line = input()
        except EOFError:
            break
        if line.strip() == "END":
            break
        lines.append(line)
    notes = "\n".join(lines).strip()
    if not notes:
        abort("Release notes are empty.")
    return notes


def confirm(new_version: str, notes: str) -> None:
    step("Summary")
    print(f"  New version: {new_version}")
    print(f"  Release notes:\n")
    for line in notes.splitlines():
        print(f"    | {line}")
    print()
    answer = input("  Proceed with release? [y/N]: ").strip().lower()
    if answer != "y":
        abort("User cancelled.")


# ---------------------------------------------------------------------------
# Steps
# ---------------------------------------------------------------------------

def check_git_clean() -> None:
    step("Checking git working tree")
    r = run("git status --porcelain", capture=True)
    if r.stdout.strip():
        print(r.stdout)
        abort("Uncommitted changes. Commit or stash them first.")
    info("Working tree clean.")


def check_git_branch() -> None:
    step(f"Checking git branch")
    r = run("git rev-parse --abbrev-ref HEAD", capture=True)
    branch = r.stdout.strip()
    if branch != DEFAULT_BRANCH:
        answer = input(f"  Current branch is '{branch}' (expected '{DEFAULT_BRANCH}'). Continue? [y/N]: ").strip().lower()
        if answer != "y":
            abort("Wrong branch.")
    else:
        info(f"On branch '{branch}'.")


def run_tests() -> None:
    step("Running tests")
    if not TESTS_RUNNER.exists():
        answer = input(f"  Test runner not found at {TESTS_RUNNER}. Skip? [y/N]: ").strip().lower()
        if answer != "y":
            abort("Tests required.")
        return
    run(f'python "{TESTS_RUNNER}"')
    info("All tests passed.")


def commit_bump(new_version: str) -> None:
    step("Committing version bump")
    files_to_add = [str(PYPROJECT)]
    if PACKAGE_INIT.exists():
        files_to_add.append(str(PACKAGE_INIT))
    # Quote each file for the shell (handles spaces in paths)
    files_quoted = " ".join(f'"{f}"' for f in files_to_add)
    run(f"git add {files_quoted}")
    run(f'git commit -m "Release v{new_version}"')


def tag_and_push(new_version: str) -> None:
    step("Tagging and pushing")
    run(f"git tag v{new_version}")
    run(f"git push origin {DEFAULT_BRANCH}")
    run(f"git push origin v{new_version}")


def clean_dist() -> None:
    step("Cleaning old dist/")
    dist_dir = PROJECT_ROOT / "dist"
    if dist_dir.exists():
        for f in dist_dir.iterdir():
            try:
                f.unlink()
                info(f"Removed {f.name}")
            except OSError:
                pass


def build_package() -> None:
    step("Building sdist + wheel")
    run("python -m build")


def upload_pypi() -> None:
    step("Uploading to PyPI")
    run("python -m twine upload dist/*")


def create_github_release(new_version: str, notes: str) -> None:
    step("Creating GitHub release")
    # Write notes to a temp file so newlines are preserved
    tmp = PROJECT_ROOT / ".release_notes.tmp"
    tmp.write_text(notes, encoding="utf-8")
    try:
        run(f'gh release create v{new_version} --title "v{new_version}" --notes-file "{tmp}"')
    finally:
        if tmp.exists():
            tmp.unlink()


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> None:
    header("Pycryptox release script")

    check_git_clean()
    check_git_branch()

    current = read_version()
    new_version = ask_new_version(current)
    if new_version == current:
        abort(f"New version ({new_version}) is the same as current.")
    notes = ask_release_notes(new_version)
    confirm(new_version, notes)

    run_tests()
    write_version(new_version)
    commit_bump(new_version)
    tag_and_push(new_version)
    clean_dist()
    build_package()
    upload_pypi()
    create_github_release(new_version, notes)

    header(f"Released v{new_version}")
    info(f"PyPI:   https://pypi.org/project/pycryptox/{new_version}/")
    info(f"GitHub: gh release view v{new_version}  (or check the repo)")


if __name__ == "__main__":
    main()