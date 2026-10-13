"""The snapshot names the account from the operating system, as the Sensor does."""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from adr_discovery import cli
from adr_discovery.world import host_identity

REPO = Path(__file__).resolve().parents[3]


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX account database")
def test_username_ignores_user_and_logname(tmp_path, monkeypatch, capsys):
    import pwd

    monkeypatch.setenv("USER", "spoofed")
    monkeypatch.setenv("LOGNAME", "spoofed")
    host_identity.username.cache_clear()

    code = cli.main(["--root", str(tmp_path), "--dry-run", "--json"])

    snapshot = json.loads(capsys.readouterr().out)
    assert code in (cli.EXIT_OK, cli.EXIT_PARTIAL)
    assert snapshot["username"] == pwd.getpwuid(os.geteuid()).pw_name != "spoofed"
    assert snapshot["hostname"] == host_identity.hostname()


@pytest.mark.skipif(not (REPO / "Common" / "sync.py").exists(), reason="outside the repository")
def test_generated_copies_match_the_shared_source():
    ran = subprocess.run([sys.executable, str(REPO / "Common" / "sync.py"), "--check"],
                         capture_output=True, text=True, check=False)
    assert ran.returncode == 0, ran.stdout + ran.stderr
