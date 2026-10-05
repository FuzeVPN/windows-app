# Diagnostics and bug reports

FuzeVPN provides local operation traces and an optional diagnostic report flow.
These are separate from account authentication and VPN connection actions.

The local trace records timestamps and bounded identifiers for areas, events
and result codes. Its API rejects arbitrary messages and does not accept
tokens, keys, tunnel configurations or raw API bodies. On Windows it lives in
the application's local data directory and rotates at a bounded size.

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
