# Security policy

## Reporting a vulnerability

Please use
[GitHub's private vulnerability report](https://github.com/FuzeVPN/windows-app/security/advisories/new)
when it is available. Otherwise use the
[official FuzeVPN website](https://fuzevpn.com) to find the current support contact
and request a secure reporting channel before sending sensitive material. Do not disclose credentials or a
working exploit in a public issue.

Include the app version, Windows version and architecture, distribution type
(installed or portable), a concise description, reproducible steps using a
test account, and the expected security impact. Redact tokens, keys, account
identifiers, IP addresses and any personal data. Maintainers may ask for a
minimal synthetic reproduction.

## Scope and releases

This repository contains the Windows client, native helpers and packaging
sources. The hosted FuzeVPN backend and third-party VPN implementations are
maintained separately. If a finding concerns an upstream component, identify
that component and its version so that it can be routed to the appropriate
maintainers.

Use the latest signed release when checking whether a problem still occurs.
The initial public source release is 1.0.6. Development builds and forks are
not official signed releases. Security fixes will be documented in release
notes; this policy does not promise a fixed response or support period.
