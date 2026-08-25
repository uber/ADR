"""Windows providers: CIM, TCP tables, Uninstall registry and AppX."""

from __future__ import annotations

import json
import shlex

from .base import Application, NullProviders, Package, Process, Socket


class WindowsProviders(NullProviders):
    reason = "Windows management surface unavailable"
    HOME_ROOTS = ("/Users",)

    def processes(self, gate):
        rows = self._ps_json(gate, "Get-CimInstance Win32_Process | Select-Object ProcessId,ParentProcessId,ExecutablePath,CommandLine | ConvertTo-Json -Compress", "processes")
        if rows is None:
            return self._unavailable(gate, "processes")
        from ..gate import Ok
        out = []
        for row in rows:
            exe = row.get("ExecutablePath")
            if not exe:
                continue
            try:
                argv = tuple(shlex.split(row.get("CommandLine") or "", posix=False))
            except ValueError:
                argv = ()
            out.append(Process(int(row.get("ProcessId") or 0), str(exe), argv,
                               int(row.get("ParentProcessId") or 0)))
        return Ok(tuple(out))

    def sockets(self, gate):
        rows = self._ps_json(gate, "Get-NetTCPConnection | Select-Object State,LocalPort,RemoteAddress,RemotePort,OwningProcess | ConvertTo-Json -Compress", "sockets")
        if rows is None:
            return self._unavailable(gate, "sockets")
        from ..gate import Ok
        states = {"Listen": "LISTEN", "Established": "ESTABLISHED"}
        return Ok(tuple(Socket("tcp", states[str(r.get("State"))], int(r.get("LocalPort") or 0),
                               str(r.get("RemoteAddress") or ""), int(r.get("RemotePort") or 0),
                               int(r.get("OwningProcess") or 0))
                        for r in rows if str(r.get("State")) in states))

    def applications(self, gate):
        script = (
            "$u=@(); $p=@('HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*',"
            "'HKLM:\\Software\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*',"
            "'HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*'); "
            "$u+=Get-ItemProperty $p -ErrorAction SilentlyContinue | Where-Object DisplayName | Select-Object @{n='Id';e={$_.PSChildName}},@{n='Name';e={$_.DisplayName}},@{n='Version';e={$_.DisplayVersion}},@{n='Vendor';e={$_.Publisher}},@{n='Path';e={$_.InstallLocation}}; "
            "$u+=Get-AppxPackage | Select-Object @{n='Id';e={$_.PackageFamilyName}},@{n='Name';e={$_.Name}},@{n='Version';e={[string]$_.Version}},@{n='Vendor';e={$_.Publisher}},@{n='Path';e={$_.InstallLocation}}; $u|ConvertTo-Json -Compress"
        )
        rows = self._ps_json(gate, script, "applications")
        if rows is None:
            return self._unavailable(gate, "applications")
        from ..gate import Ok
        return Ok(tuple(Application(str(r.get("Id") or r.get("Name") or ""), str(r.get("Name") or ""),
                                    _text(r.get("Version")), _text(r.get("Vendor")), _text(r.get("Path")))
                        for r in rows))

    def packages(self, gate):
        apps = self.applications(gate)
        if not apps.ok:
            return apps
        from ..gate import Ok
        return Ok(tuple(Package("windows", a.ident, a.version, a.path) for a in apps.value))

    def package_owner(self, gate, path):
        from ..gate import Ok, Refused
        apps = self.applications(gate)
        if not apps.ok:
            return apps
        folded = path.casefold()
        for app in apps.value:
            if app.path and folded.startswith(app.path.casefold().rstrip("\\/") + "\\"):
                return Ok(Package("windows", app.ident, app.version, app.path))
        return Refused("not_owned", path)

    def _ps_json(self, gate, script, surface):
        ran = gate.run(("powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script))
        if not ran.ok or ran.value.code != 0:
            return None
        try:
            value = json.loads(ran.value.stdout or "[]")
        except ValueError as exc:
            gate.ledger.probe(surface, "degraded", f"invalid PowerShell JSON: {exc}")
            return None
        return value if isinstance(value, list) else [value]


def _text(value):
    return str(value) if value not in (None, "") else None
