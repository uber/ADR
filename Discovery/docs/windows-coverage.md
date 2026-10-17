# Windows discovery roots and evidence

The Windows provider reads ProfileList and the User Shell Folders entries of
loaded user hives. It never loads another user's hive. ProfileImagePath and
ProfilesDirectory can be on any drive or UNC share. The caller's USERPROFILE
is retained even when other profiles exist. HKCU and the caller's APPDATA /
LOCALAPPDATA only apply to that caller; other profiles use their own registered
folders or the conventional AppData layout. Filesystem access remains gated.
Unloaded user hives can hide folder redirection, so those fallback locations do
not prove complete coverage. No Documents directory is added to the sweep.
The separate PowerShell-profile interface lists four exact filenames per user.
Native registry access requires Gate's explicit live-mode marker; this branch
must be combined with the Windows Gate changes for a complete live scan. A
legacy Gate does not cause fixture scans to inspect the host registry. Missing
or inaccessible user known-folder keys emit degraded coverage before fallback.

Windows source roots cover existing portable tool locations, redirected
Roaming/Local AppData, Chrome/Chromium/Edge/Brave and Firefox profiles, and the
configured Program Files / ProgramData roots. Managed Claude configuration is
probed under the discovered Program Files directory. Product-specific custom
browser profile locations, unopened registry hives, Jan model relocation and
arbitrary Python environments remain outside these default roots.

Language discovery reads npm manifests, pipx/uv environment directories,
Cargo manifests and Python dist-info metadata. Current-process storage
overrides are additional roots once, never templates for every user. Go module
metadata is read only from bounded PE data sections in known Go bin directories;
legacy pointer-based build info is reported unavailable. No discovered
interpreter, package manager or executable is launched. Go data beyond the
8 MiB read cap is reported degraded. Windows stable application IDs match
catalog `registry_names`; DisplayName is not identity evidence. Ollama's Windows
uninstall ID is derived from its official installer AppId plus Inno Setup's
documented `_is1` suffix; its two `.exe` names remain convention hints. No
guessed GUIDs/PFNs have been added to the catalog.

Location references used for the implementation:

- [Microsoft ProfileList](https://learn.microsoft.com/en-us/troubleshoot/windows-server/support-tools/scripts-to-cleanup-profile-folder-information-and-prevent-temp-user-profiles-from-being-created) and [known folders](https://learn.microsoft.com/en-us/windows/win32/shell/knownfolderid) describe profile and application data locations.
- [Chromium user data](https://chromium.googlesource.com/chromium/src/+/HEAD/docs/user_data_dir.md), [Edge profiles](https://learn.microsoft.com/en-us/troubleshoot/microsoft-edge/security/edge-profile-wont-load-locked), [Brave install paths](https://github.com/brave/brave-core/blob/master/chromium_src/chrome/install_static/chromium_install_modes.h), and [Firefox profiles](https://firefox-source-docs.mozilla.org/toolkit/profile/index.html) supply browser defaults.
- [npm folders](https://docs.npmjs.com/cli/v11/configuring-npm/folders/), [pipx paths](https://pipx.pypa.io/latest/how-to/configure-paths.html), and [uv storage](https://docs.astral.sh/uv/reference/storage/) specify package locations; uv tools are below the Windows persistent `uv/data` directory.
- [Python user sites](https://docs.python.org/3/library/site.html) and [Windows Python installers](https://docs.python.org/3/using/windows.html) describe the bounded Python roots. [Go buildinfo](https://go.dev/src/debug/buildinfo/buildinfo.go) documents the PE section and inline record format.
- [Claude managed settings](https://code.claude.com/docs/en/managed-settings), [Ollama Windows](https://docs.ollama.com/windows), [Hugging Face environment variables](https://huggingface.co/docs/huggingface_hub/main/package_reference/environment_variables), [LM Studio model layout](https://lmstudio.ai/docs/app/advanced/import-model), and [GPT4All settings](https://docs.gpt4all.io/gpt4all_desktop/settings.html) describe the additional configuration/model locations.
- [Ollama's installer](https://github.com/ollama/ollama/blob/main/app/ollama.iss) defines AppId `{44E83376-CE68-45EB-8FC1-393500EB558C}` and the installed executable names; [Inno Setup AppId](https://jrsoftware.org/ishelp/topic_setup_appid.htm) specifies the uninstall-key suffix.
