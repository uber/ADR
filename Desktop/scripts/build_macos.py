#!/usr/bin/env python3
"""Build a self-contained, ad-hoc-signed local macOS app. Does not publish or install hooks."""

import argparse
import os
import platform
import plistlib
import re
import shutil
import subprocess
import sys
import sysconfig
import tempfile
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def build_identity(build_number, source_revision):
    """Public, reproducible identity; never copy local paths or account details."""
    if build_number < 1:
        raise ValueError("The build number must be a positive integer")
    if source_revision and not re.fullmatch(r"[0-9a-f]{40}", source_revision):
        raise ValueError("The source revision must be a full lowercase Git commit SHA")
    project = tomllib.loads((ROOT / "pyproject.toml").read_text())["project"]
    metadata = {
        "CFBundleVersion": str(build_number),
        "CFBundleShortVersionString": project["version"],
        "ADRBuildChannel": "development",
    }
    if source_revision:
        metadata["ADRSourceRevision"] = source_revision
    return metadata


def required_python_modules():
    required = {
        "adr_desktop.api", "adr_desktop.review_supervisor", "adr_desktop.security_reviews",
        "adr_discovery.pipeline", "adr_discovery.coverage.report",
        "adr_protection.api_v1", "adr_protection.artifacts", "adr_protection.contracts",
        "adr_sensor.observer", "tabulate", "zstandard",
    }
    # Sensor parsers are dynamically selected at runtime. A successful UI
    # launch alone does not prove that every supported collector was frozen.
    required.update(
        f"adr_sensor.parsers.{source.stem}"
        for source in (ROOT.parent / "Sensor" / "adr_sensor" / "parsers").glob("*_parser.py")
    )
    return required


def validate_python_modules(listing):
    modules = {line.strip() for line in listing.splitlines()}
    missing = required_python_modules() - modules
    if missing:
        raise ValueError("The packaged core is missing Python modules: " + ", ".join(sorted(missing)))


def verify_python_bundle(core):
    result = subprocess.run(
        [
            sys.executable, "-m", "PyInstaller.utils.cliutils.archive_viewer",
            "--list", "--recursive", "--brief", str(core),
        ],
        capture_output=True, text=True, check=True, timeout=30,
    )
    validate_python_modules(result.stdout)
    print("Verified the bundled Desktop, Protection, Discovery, Sensor parsers and runtime dependencies.")


def run(*arguments):
    subprocess.run([str(argument) for argument in arguments], check=True, cwd=ROOT)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--skip-python-build", action="store_true")
    parser.add_argument("--build-number", type=int, default=1, help="Positive developer build number")
    parser.add_argument("--source-revision", help="Full Git SHA for a clean CI checkout")
    parser.add_argument(
        "--output", type=Path,
        help="Build to a staging .app path without replacing the running application",
    )
    arguments = parser.parse_args()
    try:
        identity = build_identity(arguments.build_number, arguments.source_revision)
    except ValueError as exc:
        parser.error(str(exc))
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
            # Static analysis cannot always follow setuptools' editable import
            # finders. Resolve every first-party package from this checkout.
            "--paths",
            ROOT,
            "--paths",
            ROOT.parent / "Sensor",
            "--paths",
            ROOT.parent / "Discovery",
            "--paths",
            ROOT.parent / "Protection",
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
    verify_python_bundle(core / "ADRCore")
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
            **identity,
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
