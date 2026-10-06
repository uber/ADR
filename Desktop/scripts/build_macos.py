#!/usr/bin/env python3
"""Build a self-contained, ad-hoc-signed local macOS app. Does not publish or install hooks."""

import argparse
import os
import platform
import plistlib
import shutil
import subprocess
import sys
import sysconfig
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def run(*arguments):
    subprocess.run([str(argument) for argument in arguments], check=True, cwd=ROOT)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--skip-python-build", action="store_true")
    parser.add_argument(
        "--output", type=Path,
        help="Build to a staging .app path without replacing the running application",
    )
    arguments = parser.parse_args()
    if sys.platform != "darwin":
        raise SystemExit("The menu-bar application must be built on macOS")
    build = ROOT / "build"
    dist = ROOT / "dist"
    target = (arguments.output or dist / "ADR.app").expanduser().absolute()
    if target.suffix != ".app" or target.is_symlink():
        raise SystemExit("Choose a non-symlink .app destination")
    target.parent.mkdir(parents=True, exist_ok=True)
    build.mkdir(exist_ok=True)
    dist.mkdir(exist_ok=True)
    machine = platform.machine()
    if machine not in ("arm64", "x86_64"):
        raise SystemExit("Unsupported macOS architecture")
    if not arguments.skip_python_build:
        run(
            "/usr/bin/cc",
            "-std=c11",
            "-O2",
            "-Wall",
            "-Wextra",
            ROOT / "adr_desktop" / "native" / "hook_bridge.c",
            "-o",
            build / "adr-hook",
        )
        run(
            sys.executable,
            "-m",
            "PyInstaller",
            "--noconfirm",
            "--clean",
            "--onedir",
            "--name",
            "ADRCore",
            "--distpath",
            build / "python-dist",
            "--workpath",
            build / "pyinstaller",
            "--specpath",
            build,
            "--collect-data",
            "adr_desktop",
            "--collect-data",
            "adr_discovery",
            "--collect-all",
            "adr_sensor",
            "--add-binary",
            f"{build / 'adr-hook'}:adr_desktop/bin",
            ROOT / "scripts" / "entry.py",
        )
    core = build / "python-dist" / "ADRCore"
    if not (core / "ADRCore").is_file():
        raise SystemExit("Build the Python core before using --skip-python-build")
    with tempfile.TemporaryDirectory(prefix="app-stage-", dir=build) as temporary:
        app = Path(temporary) / "ADR.app"
        contents = app / "Contents"
        binaries = contents / "MacOS"
        resources = contents / "Resources"
        resources.mkdir(parents=True)
        binaries.mkdir()
        shutil.copytree(core, resources / "core")
        sources = [
            ROOT / "native" / name
            for name in (
                "HTTPTransport.swift",
                "LocalVault.swift",
                "LocalVaultSelfTests.swift",
                "FileAccess.swift",
                "Vault.swift",
                "EnvironmentVault.swift",
                "VaultProcess.swift",
                "SelfTests.swift",
                "main.swift",
            )
        ]
        run(
            "xcrun",
            "swiftc",
            "-swift-version",
            "5",
            "-O",
            "-target",
            f"{machine}-apple-macosx13.0",
            "-framework",
            "Cocoa",
            "-framework",
            "Security",
            "-framework",
            "Network",
            "-framework",
            "ServiceManagement",
            "-framework",
            "CFNetwork",
            *sources,
            "-o",
            binaries / "ADR",
        )
        info = {
            "CFBundleName": "ADR",
            "CFBundleDisplayName": "ADR",
            "CFBundleExecutable": "ADR",
            "CFBundleIdentifier": "org.adr.Desktop",
            "CFBundleVersion": "1",
            "CFBundleShortVersionString": "0.1.0",
            "CFBundlePackageType": "APPL",
            "LSUIElement": True,
            "LSMinimumSystemVersion": str(
                max(13, int(str(sysconfig.get_config_var("MACOSX_DEPLOYMENT_TARGET") or "13").split(".")[0]))
            )
            + ".0",
            "NSHighResolutionCapable": True,
            "NSHumanReadableCopyright": "ADR Project Contributors. Apache License 2.0.",
        }
        with (contents / "Info.plist").open("wb") as handle:
            plistlib.dump(info, handle)
        shutil.copy2(ROOT.parent / "LICENSE", resources / "LICENSE")
        # Sign the native vault host and seal the local development bundle.
        # Distribution releases need a Developer ID and notarization separately.
        run("codesign", "--force", "--sign", "-", "--options", "runtime", app)
        run("codesign", "--verify", "--deep", "--strict", app)
        if target.exists():
            previous = target.with_name(f"{target.stem}.previous-{os.getpid()}.app")
            if previous.exists():
                raise SystemExit(f"Refusing to overwrite an existing backup: {previous}")
            target.rename(previous)
            print(f"Previous local build preserved at {previous}")
        shutil.move(str(app), str(target))
    print(f"Built {target}")
    print("Local developer build only; no PR, release, or hook installation was performed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
