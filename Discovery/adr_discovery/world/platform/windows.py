"""Windows providers: CIM, TCP tables, Uninstall registry, AppX and DNS cache."""

from __future__ import annotations

import json
import shlex

from .base import Application, DnsEntry, HostResolver, NullProviders, Package, Process, Socket
from .windows_system import powershell_path

_PS_PREFIX = (
    "$ErrorActionPreference='Stop'; $ProgressPreference='SilentlyContinue'; "
    "$PSModuleAutoLoadingPreference='None'; "
    "[Console]::OutputEncoding=[System.Text.UTF8Encoding]::new($false); "
    "$OutputEncoding=[Console]::OutputEncoding; "
)
_APPLICATION_SOURCES = (
    "applications:machine", "applications:machine32", "applications:current_user", "applications:appx_current_user",
)
_OTHER_TCP_STATES = frozenset({
    "Closed", "SynSent", "SynReceived", "FinWait1", "FinWait2", "CloseWait",
    "Closing", "LastAck", "TimeWait", "DeleteTCB", "Bound",
})


def _import_module(name: str) -> str:
    """Import only scanner-owned names from the trusted system PSHOME.

    Autoloading can scan module metadata beyond the helper's time budget;
    explicit imports keep both lookup and execution under the bounded helper.
    Names here are constants, never inventory data or environment variables.
    """
    return ("Import-Module ($PSHOME+'\\Modules\\" + name + "\\" + name
            + ".psd1') -ErrorAction Stop; ")


class WindowsProviders(HostResolver, NullProviders):
    reason = "Windows management surface unavailable"
    HOME_ROOTS = ("/Users",)
    DIRECT_HOMES: tuple[str, ...] = ()

    def default_owner(self) -> str:
        return "unknown"

    def owner_of(self, uid: int) -> str:
        # Windows st_uid does not identify the ACL owner. Do not attribute an
        # unread account to SYSTEM, which participates in asset merge keys.
        return self.default_owner()

    def processes(self, gate):
        from ..gate import Ok

        rows = self._ps_json(
            gate,
            "Get-CimInstance Win32_Process -ErrorAction Stop | "
            "Select-Object ProcessId,ParentProcessId,ExecutablePath,CommandLine | ConvertTo-Json -Compress",
            "processes",
        )
        if not rows.ok:
            return rows
        out, missing_paths, invalid = [], 0, 0
        for row in rows.value:
            exe = _text(row.get("ExecutablePath"))
            if not exe:
                missing_paths += 1
                continue
            pid = _number(row.get("ProcessId"), minimum=1)
            parent = _number(row.get("ParentProcessId", 0))
            if pid is None or parent is None:
                invalid += 1
                continue
            command = row.get("CommandLine")
            if command is not None and not isinstance(command, str):
                invalid += 1
                command = ""
            try:
                argv = tuple(shlex.split(command or "", posix=False))
            except ValueError:
                argv = ()
                invalid += 1
            out.append(Process(pid, exe, argv, parent, user="unknown"))
        if missing_paths:
            gate.ledger.unavailable("process_paths", f"{missing_paths} processes have no readable executable path")
        _omitted(gate, "processes", invalid)
        if out:
            gate.ledger.unavailable("process_owners", "Windows process account lookup is not implemented")
        return Ok(tuple(out))

    def sockets(self, gate):
        from ..gate import Ok

        rows = self._ps_json(
            gate,
            "Get-NetTCPConnection -ErrorAction Stop | "
            "Select-Object @{n='State';e={[string]$_.State}},LocalPort,RemoteAddress,RemotePort,OwningProcess | "
            "ConvertTo-Json -Compress",
            "sockets",
        )
        if not rows.ok:
            return rows
        states = {"Listen": "LISTEN", "Established": "ESTABLISHED", "2": "LISTEN", "5": "ESTABLISHED",
                  2: "LISTEN", 5: "ESTABLISHED"}
        out, invalid = [], 0
        for row in rows.value:
            state = row.get("State")
            if isinstance(state, str) and state in _OTHER_TCP_STATES:
                continue
            if not isinstance(state, (str, int)) or isinstance(state, bool) or state not in states:
                invalid += 1
                continue
            local_port = _number(row.get("LocalPort"), maximum=65535)
            remote_port = _number(row.get("RemotePort", 0), maximum=65535)
            pid = _number(row.get("OwningProcess", 0))
            remote = _text(row.get("RemoteAddress")) or ""
            if local_port is None or remote_port is None or pid is None or (states[state] == "ESTABLISHED" and not remote):
                invalid += 1
                continue
            out.append(Socket("tcp", states[state], local_port, remote, remote_port, pid or None))
        _omitted(gate, "sockets", invalid)
        return Ok(tuple(out))

    def applications(self, gate):
        from ..gate import Ok

        # One bounded helper, but separate results for every source: an AppX
        # failure must not discard readable uninstall records or look empty.
        script = (
            "$results=@(); $sources=@("
            "@{Source='applications:machine';Path='HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall'},"
            "@{Source='applications:machine32';Path='HKLM:\\Software\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall'},"
            "@{Source='applications:current_user';Path='HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall'}); "
            "foreach($source in $sources){ try { "
            + _import_module("Microsoft.PowerShell.Management") + "$rows=@(); "
            "if(Test-Path -LiteralPath $source.Path -ErrorAction Stop){ "
            "$rows=@(Get-ChildItem -LiteralPath $source.Path -ErrorAction Stop | "
            "ForEach-Object {Get-ItemProperty -LiteralPath $_.PSPath -ErrorAction Stop} | "
            "Where-Object DisplayName | Select-Object "
            "@{n='Id';e={$_.PSChildName}},@{n='Name';e={$_.DisplayName}},"
            "@{n='Version';e={$_.DisplayVersion}},@{n='Vendor';e={$_.Publisher}},@{n='Path';e={$_.InstallLocation}}); }; "
            "$results+=[pscustomobject]@{Source=$source.Source;Ok=$true;Rows=$rows}; "
            "} catch { $results+=[pscustomobject]@{Source=$source.Source;Ok=$false;Error=$_.Exception.GetType().Name}; } }; "
            "try { " + _import_module("Appx") + "$rows=@(Get-AppxPackage -ErrorAction Stop | Select-Object "
            "@{n='Id';e={$_.PackageFamilyName}},@{n='Name';e={$_.Name}},"
            "@{n='Version';e={[string]$_.Version}},@{n='Vendor';e={$_.Publisher}},@{n='Path';e={$_.InstallLocation}}); "
            "$results+=[pscustomobject]@{Source='applications:appx_current_user';Ok=$true;Rows=$rows}; "
            "} catch { $results+=[pscustomobject]@{Source='applications:appx_current_user';Ok=$false;Error=$_.Exception.GetType().Name}; }; "
            "$results | ConvertTo-Json -Depth 4 -Compress"
        )
        gate.ledger.unavailable(
            "applications:other_users", "other users' per-user uninstall keys and AppX packages are not queried",
        )
        rows = self._ps_json(gate, script, "applications")
        if not rows.ok:
            return rows
        out, seen, readable = [], set(), 0
        for source in rows.value:
            name = source.get("Source")
            if not isinstance(name, str) or name not in _APPLICATION_SOURCES or name in seen:
                _omitted(gate, "applications", 1)
                continue
            seen.add(name)
            if source.get("Ok") is not True:
                error = source.get("Error")
                # Report exception types, never raw PowerShell error messages
                # that may contain user paths, command lines or record values.
                detail = error if isinstance(error, str) and error.isascii() and error.isidentifier() else "query failed"
                self._failed(gate, name, detail)
                continue
            records = self._rows(gate, source.get("Rows"), name)
            if not records.ok:
                continue
            readable += 1
            invalid, count = 0, 0
            for row in records.value:
                ident, display = _text(row.get("Id")), _text(row.get("Name"))
                if not ident or not display:
                    invalid += 1
                    continue
                invalid += sum(row.get(field) is not None and not isinstance(row.get(field), str)
                               for field in ("Version", "Vendor", "Path"))
                out.append(Application(ident, display, _text(row.get("Version")),
                                       _text(row.get("Vendor")), _text(row.get("Path"))))
                count += 1
            _omitted(gate, name, invalid)
            gate.ledger.probe(name, "ran", f"{count} records")
        for name in _APPLICATION_SOURCES:
            if name not in seen:
                self._failed(gate, name, "source result missing from PowerShell output")
        if not readable:
            return self._failed(gate, "applications", "no application source could be read")
        return Ok(tuple(out))

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

    def dns_cache(self, gate):
        from ..gate import Ok

        rows = self._ps_json(
            gate, "Get-DnsClientCache -ErrorAction Stop | Select-Object Entry,Name | ConvertTo-Json -Compress", "dns_cache",
        )
        if not rows.ok:
            return rows
        names, invalid = set(), 0
        for row in rows.value:
            name = _text(row.get("Entry")) or _text(row.get("Name"))
            if not name or not name.rstrip("."):
                invalid += 1
                continue
            names.add(name.rstrip(".").casefold())
        _omitted(gate, "dns_cache", invalid)
        return Ok(tuple(DnsEntry(name) for name in sorted(names) if name))

    def exec_journal(self, gate):
        return self._failed(gate, "exec_journal", "Windows execution history requires an explicitly configured collector")

    def _ps_json(self, gate, script, surface):
        try:
            helper = powershell_path()
        except OSError:
            return self._failed(gate, surface, "trusted Windows PowerShell location is unavailable")
        modules = ("Microsoft.PowerShell.Utility",)
        if surface == "processes":
            modules += ("CimCmdlets",)
        elif surface == "sockets":
            modules += ("CimCmdlets", "NetTCPIP")
        elif surface == "dns_cache":
            modules += ("CimCmdlets", "DnsClient")
        imports = "".join(_import_module(module) for module in modules)
        ran = gate.run_helper((helper, "-NoLogo", "-NoProfile", "-NonInteractive", "-Command", _PS_PREFIX + imports + script))
        if not ran.ok:
            return self._failed(gate, surface, f"PowerShell helper refused: {ran.reason}")
        if ran.value.code != 0:
            return self._failed(gate, surface, f"PowerShell exited with code {ran.value.code}")
        try:
            value = json.loads(ran.value.stdout.lstrip("\ufeff").strip() or "[]")
        except (ValueError, RecursionError):
            return self._failed(gate, surface, "invalid PowerShell JSON")
        return self._rows(gate, value, surface)

    @staticmethod
    def _rows(gate, value, surface):
        from ..gate import Ok

        if isinstance(value, dict):
            return Ok((value,))
        if not isinstance(value, list):
            return WindowsProviders._failed(gate, surface, "PowerShell JSON is not an object or array")
        rows = tuple(row for row in value if isinstance(row, dict))
        _omitted(gate, surface, len(value) - len(rows))
        if value and not rows:
            return WindowsProviders._failed(gate, surface, "PowerShell JSON contains no valid records")
        return Ok(rows)

    @staticmethod
    def _failed(gate, surface, reason):
        from ..gate import Refused

        gate.ledger.unavailable(surface, reason)
        return Refused("unavailable", reason)


def _text(value):
    return value if isinstance(value, str) and value else None


def _number(value, *, minimum=0, maximum=0xFFFFFFFF):
    if isinstance(value, bool) or not isinstance(value, (str, int)):
        return None
    try:
        number = int(value)
    except ValueError:
        return None
    return number if minimum <= number <= maximum else None


def _omitted(gate, surface, count):
    if count:
        gate.ledger.unavailable(f"{surface}:records", f"{count} records or fields were unavailable or invalid")
