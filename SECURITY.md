# Security policy

## Reporting a vulnerability in SurfaceScope

Please use the repository's private vulnerability reporting channel under the GitHub
**Security** tab. Do not open a public issue for a vulnerability in SurfaceScope itself.

Include:

- affected version or commit;
- operating system and Python version;
- a minimal reproduction using a loopback or synthetic target;
- impact and whether credentials, files or third-party systems are involved.

Do not include real client data, access tokens or third-party scan results in a report.

## Authorized use

SurfaceScope is intended only for systems you own or are explicitly authorized to test.
Before scanning, confirm the target scope, time window, allowed test types and request
budget with the system owner.

The default configuration enables low-risk discovery only. 403/401 review, Swagger and
Packer stages are opt-in. Unsafe writes, SQLi probes and active Packer checks require
explicit command-line options.

## Data handling

- Reports and logs may contain target URLs, headers or truncated secret previews.
- Store reports in an access-controlled location.
- Do not upload reports to public issues, paste sites or public repositories.
- Delete local evidence according to the authorization agreement.
- Packer secret findings are stored as redacted previews, not full credentials.

## Dependency and transport boundaries

The runtime does not download tools, create component virtual environments or execute
upstream binaries. Requests go through the shared executor with explicit budgets and
authorization scope. This reduces supply-chain risk but does not make the scanner safe to
use against unauthorized targets.
