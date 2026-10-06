# Bundled malicious-artifact intelligence

`malicious_artifacts.json` is a small reviewed offline baseline, not a complete
malware catalog or a vulnerability database. Its publication timestamp describes
this ADR baseline, not the age or completeness of the underlying threat reports.

The four records cite public primary disclosures: eight exact package releases
and one malicious binary hash. There are currently **no skill-manifest hashes or
MCP endpoint indicators**. Unknown artifacts and incomplete identities do not
receive a safety certificate.

Records match exact package registry/name/version identities or complete raw
file bytes. The PyTorch digest belongs to the disclosed `triton/runtime/triton`
binary, not an archive or `SKILL.md`. Vulnerability-only reports are not evidence
that a package is malicious. No artifact was downloaded or executed to create
this baseline.

The feed is inert JSON. References are not fetched during enforcement. The
owner may import an additive private local feed; it cannot impersonate or revoke
the bundled namespace. There is no network updater or automatic submission.
