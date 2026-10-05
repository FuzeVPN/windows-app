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
TLS failures classify the detail from both Dart exception fields into fixed
references (issuer missing, expired certificate, hostname mismatch and others).
Their BoringSSL status is labelled `tls_error`, not a Windows error code.
For a missing issuer on the fixed API host, Windows builds and verifies the
certificate chain in a background worker. Dart's bad-certificate callback can
provide the failing issuer rather than the server leaf. An explicitly marked
CA requires strict BASE chain policy and server-authentication usage; a server
leaf requires SSL policy with the exact API hostname. Only successful policy
verification can return a distinct, trusted, self-signed root. The client then
creates a fresh trust context and performs at most one new TLS handshake,
which verifies the actual server leaf, chain and hostname before any HTTP data.
A failed Windows check, unavailable bridge, cancellation or rejected retry
never permits HTTP traffic. The local trace includes verification/retry stages,
numeric trust status and fixed certificate roles (`ca_chain` or
`server_certificate`); certificate contents are never included in the trace
or diagnostic report.
Each address attempt is retained even if a later attempt fails differently.
Its API rejects arbitrary messages and does not accept
tokens, keys, tunnel configurations or raw API bodies. On Windows it lives in
`%LOCALAPPDATA%\FuzeVPN\diagnostic.log` and rotates at a bounded size.

From version **1.0.7**, **Diagnostics** has one **Diagnostic** action. It runs
available checks, reads the bounded current and rotated application trace,
collects the sanitized native trace, and queries the Windows Service Control
Manager directly. It prepares and sends one complete report using the active
account. The service observation remains available when the broker is broken;
it does not start a service, elevate, disconnect or repair the VPN. During a VPN
operation, checks that cannot safely run are explicitly marked as unavailable,
while the passive evidence is still collected. No PowerShell command or manual
log-file retrieval is required.

The same complete document appears inline and can be selected or copied with
the normal text context menu. Without an account it can still be collected;
the application explicitly reports that authenticated delivery is unavailable.
Offline delivery retains the exact frozen report in the existing bounded queue.
It is marked received only after a valid server receipt. A missing, unreadable,
rejected or timed-out source is identified in the report and does not erase the
other sources. Current and persisted application events are deduplicated and
merged with native events in a timestamped timeline with an explicit source.

Complete manual Windows reports add the closed **`windows.support`** extension
to **`POST /v1/diagnostics`**, with source availability, service state and exit
codes, component versions and the merged timeline. Existing version-1 fields,
automatic simple reports, account authentication, idempotence and retention stay
as defined by the diagnostic contract. **Deploy server support for this optional
extension before releasing 1.0.7**: an unextended server rejects it with HTTP 400
`invalid_diagnostic`. No reduced report is silently substituted.

Collection is capped at 256 KiB/1,024 application events and 64 KiB/128 native
events, with an explicit truncation/discard count. Only closed technical
identifiers, numeric measurements and validated timestamps are accepted.
Arbitrary text, credentials, addresses, paths and account data are rejected.
Error cards show the local error reference and any available Windows or
observed HTTP status.
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
