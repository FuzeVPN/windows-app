# Diagnostics and bug reports

FuzeVPN provides local operation traces and an optional diagnostic report flow.
These are separate from account authentication and VPN connection actions.

The local trace records timestamps and bounded identifiers for areas, events
and result codes. Startup, local storage, session recovery, native observations
and update operations record their individual stages. HTTPS requests record
native resolution, each TCP/TLS attempt, request transmission, response receipt,
body reading and JSON decoding, with correlated request identifiers and durations.
Persistent socket errors carry a connection identifier rather than attributing
the error to the request that originally opened the connection.
Observed HTTP statuses and numeric Windows errors are retained; a locally
synthesized error is never presented as an HTTP response from the server.
Each address attempt is retained even if a later attempt fails differently.
Its API rejects arbitrary messages and does not accept
tokens, keys, tunnel configurations or raw API bodies. On Windows it lives in
`%LOCALAPPDATA%\FuzeVPN\diagnostic.log` and rotates at a bounded size.

In **Diagnostics**, use **Local timeline** to inspect the current session's
stages, and **Copy local diagnostic** to copy the report and timeline together.
These controls work without signing in. The local timeline is not automatically
included in the version-1 server report or sent to the service. Error cards show
the local error reference and any available Windows or observed HTTP status.
Failures of local runtime, storage or resolution are labelled by that component;
an unsuccessful connection attempt does not by itself establish a server outage.

Diagnostic collection observes native runtime and protection state. Collection
and sharing are controlled through the diagnostic interface and its consent
flow. An unavailable observation is reported as unavailable rather than as
proof of disconnection. A local trace is not a packet capture or proof of a
working VPN tunnel.

For a public bug report, include:

- App version, Windows version and x64 or ARM64 architecture.
- Installed, portable or local development mode.
- Steps to reproduce using a test account or synthetic data.
- Expected and observed behaviour, including the displayed error code if present.
- Checks performed and whether the problem occurs in the latest signed release.

Do not attach application-storage exports, account identifiers, tokens, VPN
keys, real tunnel configurations, private API responses or unredacted user
logs. Review screenshots and report content before sharing. Use the private
process in [SECURITY.md](../SECURITY.md) for a potential vulnerability.

Automated tests inject storage and native-bridge doubles. Use an isolated test
profile from [development](development.md) when running them locally.
