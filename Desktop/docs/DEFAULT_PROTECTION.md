# Starter file protection

Connect a protection hook, then choose **File protection → Add starter protections** to add a baseline of
**Block** rules. Expand **Review standard paths** first to see the exact
locations for the current user's home directory. This is optional: launching
or updating ADR does not add rules or install hooks. The API also rejects the
starter action until a hook is configured for that same ADR profile.

## Included paths

The macOS set has 13 paths. Linux uses the same set except for macOS Keychain
files. Windows starter paths and native Windows enforcement are not included
in this preview.

| Credential store | Standard path | Why it is included |
| --- | --- | --- |
| [macOS Keychain files](https://support.apple.com/guide/keychain-access/copy-keychains-to-another-mac-kyca1121/mac) | `~/Library/Keychains/` | User Keychain databases. Protects direct file access, not Keychain APIs. |
| [SSH](https://man.openbsd.org/ssh) | `~/.ssh/` | Private keys, including custom-named keys, and SSH configuration. The whole folder is covered, including public keys and known-host files. |
| [GnuPG](https://www.gnupg.org/documentation/manuals/gnupg/GPG-Configuration.html) | `~/.gnupg/` | The key store, including private keys and legacy secret-key files. Public-key files in this folder are also covered. |
| [AWS CLI](https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-files.html) | `~/.aws/` | Shared credentials, role-credential caches, and SSO token caches. |
| [Google Cloud CLI](https://docs.cloud.google.com/sdk/docs/configurations) | `~/.config/gcloud/` | CLI credentials and application-default credentials. |
| [Azure CLI](https://learn.microsoft.com/en-us/cli/azure/azure-cli-configuration) | `~/.azure/` | CLI authentication caches and account configuration. |
| [Kubernetes](https://kubernetes.io/docs/concepts/configuration/organize-cluster-access-kubeconfig/) | `~/.kube/config` | Cluster credentials and references to client keys. Referenced files elsewhere need separate rules. |
| [Docker](https://docs.docker.com/reference/cli/docker/login/) | `~/.docker/config.json` | Registry authentication, including inline credentials when no external credential store is used. |
| [Git credential store](https://git-scm.com/docs/git-credential-store) | `~/.git-credentials`, `~/.config/git/credentials` | Git's two standard plaintext credential-store locations. |
| [npm](https://docs.npmjs.com/cli/v11/configuring-npm/npmrc/) | `~/.npmrc` | User-level registry authentication and tokens. |
| [Python package publishing](https://packaging.python.org/en/latest/specifications/pypirc/) | `~/.pypirc` | Package-index upload passwords or API tokens. |
| [Network clients](https://curl.se/docs/manpage.html) | `~/.netrc` | Hostnames and login credentials used by curl and other clients. |

No credential contents are read to prepare or apply the set. ADR checks path
metadata and aliases to avoid duplicates and unsafe broad rules. A location
does not need to exist yet: the rule also applies if it is created later.
Directories cover their contents; file rules cover the named file.

## Existing choices stay yours

- Existing Block or Ask first rules covering a proposed path are kept.
- A default folder rule is skipped if it would overlap a more specific custom
  rule. Adding a parent Block could otherwise silently override an Ask first
  choice. The preview labels these locations **Custom rule kept**, not fully
  blocked.
- Applying the set twice does not duplicate rules. Missing rules are added
  together; a storage failure or the rule-count limit does not partially apply
  a set.
- Unsafe or unresolvable paths are marked for manual review. A credential-folder
  symlink pointing at the entire home directory or filesystem root is not
  converted into a broad Block rule.
- Paused file rules stay paused. Capture settings, credential grants, login
  settings, and agent-hook configuration are not changed.
- The setup card disappears after the set is added. Expand **Starter rules**
  under **Your file rules** to remove any rule.
  To use Ask first instead, remove that Block rule and add your own rule for
  the same path. **Restore missing starter rules** preserves that choice.

## Enforcement and limits

Rules are enforced through connected ADR hooks for supported agent harnesses.
If no hook is connected, saved rules are labeled inactive and the starter action
is disabled. Configured hooks awaiting restart are distinguished from reported
hook activity. Adding the
set does not modify filesystem permissions or Keychain access controls.
The persisted rules also work through the offline hook.

This is a starter set of standard locations, not complete secret discovery.
Environment overrides such as `GNUPGHOME`, `AWS_SHARED_CREDENTIALS_FILE`,
`CLOUDSDK_CONFIG`, `AZURE_CONFIG_DIR`, `KUBECONFIG`, `DOCKER_CONFIG`, or
`XDG_CONFIG_HOME` can move credentials elsewhere. Add those custom locations
explicitly, along with project `.env` files, private certificates, browser
profiles, and any other crown-jewel files you want covered. Documents,
Downloads, repositories, and the entire home directory are not default blocks.

A direct file-tool request can be blocked by path. An operating-system
credential API, a shell command, or an unclassified MCP tool can access data
indirectly; ADR cannot prove every file it will touch and applies the existing
Ask first / Block policy for those opaque operations. These are cooperative
agent controls, not a system-wide sandbox or a guarantee that a credential
cannot be accessed by another process. File rules do not redact already
captured session history. See the [security model](SECURITY.md).
