"""
install_pycryptox_pq.py
Automated Windows installer for Pycryptox post-quantum dependencies.

Usage:
    python install_pycryptox_pq.py

Installs (via winget): CMake, Git, Visual Studio 2022 Build Tools (C++ workload).
Then: pip install liboqs-python, triggers first import (builds liboqs C lib),
runs a ML-KEM-512 round-trip sanity check.

Total time: ~15-25 min on first run. UAC prompts may appear during winget steps.
Subsequent runs are fast (winget detects already-installed packages and skips).
"""

import os
import shutil
import subprocess
import sys


def main() -> int:
    if sys.platform != "win32":
        print("This script is Windows-only. For Linux/macOS, use the manual instructions.")
        return 1

    import winreg

    if shutil.which("winget") is None:
        print("ERROR: 'winget' not found.")
        print("       Install 'App Installer' from the Microsoft Store first,")
        print("       then reopen this terminal and run this script again.")
        return 1

    print("=" * 60)
    print("Pycryptox PQ deps installer (Windows)")
    print("=" * 60)
    print("Will install via winget (UAC prompts may appear):")
    print("  - CMake")
    print("  - Git")
    print("  - Visual Studio 2022 Build Tools (C++ workload, ~5 GB)")
    print("Then: pip install liboqs-python, build liboqs, run sanity check.")
    print("Total time: ~15-25 min on first run.\n")
    try:
        input("Press Enter to start (or Ctrl-C to cancel)... ")
    except KeyboardInterrupt:
        print("\nCancelled.")
        return 1

    # Step 1: winget installs. Idempotent -- skips if already installed.
    winget_targets = [
        ("Kitware.CMake", "CMake", []),
        ("Git.Git", "Git", []),
        (
            "Microsoft.VisualStudio.2022.BuildTools",
            "Visual Studio 2022 Build Tools (C++ workload)",
            [
                "--override",
                "--quiet --wait "
                "--add Microsoft.VisualStudio.Workload.VCTools "
                "--includeRecommended",
            ],
        ),
    ]
    for pkg_id, name, extra in winget_targets:
        print(f"\n--- Installing {name} ---")
        cmd = [
            "winget", "install", "--id", pkg_id,
            "--accept-package-agreements",
            "--accept-source-agreements",
            "--silent",
        ] + extra
        subprocess.run(cmd)

    # Step 2: refresh PATH from registry so child subprocesses see the new tools.
    def _refresh_path() -> None:
        paths = []
        try:
            with winreg.OpenKey(
                winreg.HKEY_LOCAL_MACHINE,
                r"SYSTEM\CurrentControlSet\Control\Session Manager\Environment",
            ) as k:
                paths.append(winreg.QueryValueEx(k, "Path")[0])
        except OSError:
            pass
        try:
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, "Environment") as k:
                paths.append(winreg.QueryValueEx(k, "Path")[0])
        except OSError:
            pass
        if paths:
            os.environ["PATH"] = ";".join(paths)

    _refresh_path()

    print("\n--- PATH refreshed ---")
    print(f"  cmake: {shutil.which('cmake') or 'NOT FOUND'}")
    print(f"  git:   {shutil.which('git') or 'NOT FOUND'}")
    if not shutil.which("cmake") or not shutil.which("git"):
        print("\nWARNING: cmake or git missing from PATH after install.")
        print("         Close this terminal, open a new one, then re-run this script.")
        return 1

    # Step 3: pip install liboqs-python.
    print("\n--- pip install liboqs-python ---")
    r = subprocess.run([sys.executable, "-m", "pip", "install", "liboqs-python"])
    if r.returncode != 0:
        print("ERROR: pip install failed. See output above.")
        return 1

    # Step 4: first import + ML-KEM-512 sanity check.
    print("\n--- First import (auto-builds liboqs C library, 2-5 min) ---")
    sanity = (
        "import oqs\n"
        "with oqs.KeyEncapsulation('ML-KEM-512') as kem:\n"
        "    pub = kem.generate_keypair()\n"
        "    priv = kem.export_secret_key()\n"
        "    ct, ss1 = kem.encap_secret(pub)\n"
        "with oqs.KeyEncapsulation('ML-KEM-512', secret_key=priv) as kem:\n"
        "    ss2 = kem.decap_secret(ct)\n"
        "assert ss1 == ss2, 'KEM round-trip failed'\n"
        "print(f'OK pub={len(pub)}B priv={len(priv)}B ct={len(ct)}B')\n"
    )
    r = subprocess.run([sys.executable, "-c", sanity])
    if r.returncode != 0:
        print("\nERROR: sanity check failed. Common causes:")
        print("  1. VS Build Tools install incomplete: open Visual Studio Installer,")
        print("     verify 'Desktop development with C++' workload is checked.")
        print("  2. MSVC env not picked up: try running this script from a")
        print("     'x64 Native Tools Command Prompt for VS 2022' (Start menu).")
        return 1

    print("\n" + "=" * 60)
    print("DONE. liboqs-python is installed and works.")
    print("You can now run your Pycryptox tests.")
    print("=" * 60)
    return 0


if __name__ == "__main__":
    sys.exit(main())