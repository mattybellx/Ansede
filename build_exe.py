"""
ansede-static Nuitka Build Configuration
────────────────────────────────────────
Produces a standalone .exe for Windows (x64) with zero Python dependency.

Usage:
    pip install nuitka
    python build_exe.py

Output:
    dist/ansede-static.exe  (~15-20 MB standalone executable)
    dist/ansede-static-lsp.exe  (LSP server standalone)

Requirements:
    - Nuitka >= 2.0
    - Windows: MinGW-w64 or MSVC (Visual Studio Build Tools)
    - macOS/Linux: GCC or Clang
"""
from __future__ import annotations

import os
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
DIST = ROOT / "dist"
BUILD = ROOT / "build" / "nuitka"


def check_nuitka() -> bool:
    """Check if Nuitka is installed."""
    try:
        result = subprocess.run(
            [sys.executable, "-m", "nuitka", "--version"],
            capture_output=True,
            text=True,
        )
        return result.returncode == 0
    except Exception:
        return False


def clean() -> None:
    """Remove previous build artifacts."""
    for path in (DIST, BUILD):
        if path.exists():
            shutil.rmtree(path)
    DIST.mkdir(parents=True, exist_ok=True)


def build_target(
    entry_point: str,
    output_name: str,
    *,
    console: bool = True,
    icon: str | None = None,
) -> Path:
    """Build a single Nuitka target."""
    cmd = [
        sys.executable, "-m", "nuitka",
        "--standalone",
        "--onefile",
        "--assume-yes-for-downloads",
        f"--output-dir={DIST}",
        f"--output-filename={output_name}",
    ]

    if console:
        cmd.append("--windows-console-mode=force")
    else:
        cmd.append("--windows-console-mode=disable")

    if icon and Path(icon).exists():
        cmd.append(f"--windows-icon-from-ico={icon}")

    # Performance optimizations
    cmd.extend([
        "--lto=yes",
        "--python-flag=-OO",
        "--remove-output",
        "--include-windows-runtime-dlls=no",
    ])

    # Entry point
    if entry_point.endswith(".py"):
        cmd.append(str(ROOT / entry_point))
    else:
        cmd.extend(["--module", entry_point])

    print(f"  Building {output_name}...")
    result = subprocess.run(cmd, cwd=str(ROOT))
    if result.returncode != 0:
        print(f"  ❌ Failed to build {output_name}")
        sys.exit(1)

    output_path = DIST / output_name
    if output_path.exists():
        size_mb = output_path.stat().st_size / (1024 * 1024)
        print(f"  ✅ {output_name} ({size_mb:.1f} MB)")
    return output_path


def main() -> None:
    print("ansede-static Nuitka Builder")
    print("=" * 50)

    if not check_nuitka():
        print("\n❌ Nuitka is not installed.")
        print("   Install with: pip install nuitka")
        print("   Also requires a C compiler (MSVC or MinGW on Windows).")
        sys.exit(1)

    clean()

    # Find icon
    icon = None
    for candidate in (
        ROOT / "branding" / "ansede.ico",
        ROOT / "assets" / "ansede.ico",
    ):
        if candidate.exists():
            icon = str(candidate)
            break

    # Build CLI
    print("\nBuilding ansede-static CLI...")
    build_target(
        entry_point="src/ansede_static/cli.py",
        output_name="ansede-static.exe" if os.name == "nt" else "ansede-static",
        console=True,
        icon=icon,
    )

    # Build LSP server
    print("\nBuilding ansede-static LSP server...")
    build_target(
        entry_point="src/ansede_static/lsp_server.py",
        output_name="ansede-static-lsp.exe" if os.name == "nt" else "ansede-static-lsp",
        console=False,
        icon=icon,
    )

    # Copy supporting files
    print("\nCopying supporting files...")
    for src, dst_name in [
        ("README.md", "README.txt"),
        ("LICENSE", "LICENSE.txt"),
        ("CHANGELOG.md", "CHANGELOG.txt"),
    ]:
        src_path = ROOT / src
        if src_path.exists():
            shutil.copy2(src_path, DIST / dst_name)

    print("\n" + "=" * 50)
    print("Build complete! Artifacts in dist/")
    print(f"  {DIST}")
    print()
    print("To distribute:")
    print("  1. Zip the dist/ folder")
    print("  2. Sign ansede-static.exe with your code signing certificate")
    print("  3. Upload to your distribution channel")

    # Optional: create zip
    zip_name = "ansede-static-windows-x64.zip"
    print(f"\nCreating {zip_name}...")
    shutil.make_archive(
        str(DIST.parent / zip_name.replace(".zip", "")),
        "zip",
        DIST,
    )
    print(f"  ✅ {zip_name}")


if __name__ == "__main__":
    main()
