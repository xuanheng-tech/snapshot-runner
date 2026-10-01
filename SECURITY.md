# Security reporting

Snapshot Runner trusts the current user and OS and treats repository contents and
captured evidence as untrusted data. It does not provide isolation from malicious
processes running as the same user. See [README.md](README.md) for execution, redaction,
platform and size boundaries. Artifacts need human review before being shared.

For a suspected vulnerability, use **Report a vulnerability** in the repository's
GitHub Security tab if private reporting is enabled. If that option is unavailable,
open an issue containing only a request for a private reporting channel; do not post
credentials, private paths, artifact bodies or a sensitive exploit there. There is no
promised response deadline or support policy for older releases.

Provide the package and Git versions, verified platform, affected command, expected
boundary and a minimal reproduction using a disposable repository with synthetic data.
Never include real secrets. Report the observed impact separately from assumptions.
