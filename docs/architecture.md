# Architecture

The Windows client combines a Flutter interface with native C++ code and
separate processes for privileged operations. The repository publishes the
client; the hosted FuzeVPN API and VPN servers are separate services.

| Area | Source | Responsibility |
| --- | --- | --- |
| Interface and application state | `lib/` | Account, device and location flows, preferences, connection lifecycle and translations |
| Native Flutter channels | `windows/runner/` | Bridge between Dart and Windows facilities |
| Privileged broker | `fuzevpn_service` target | Restricted native commands for installed mode |
| Portable helper | `fuzevpn_runtime` target | Privileged runtime for portable mode |
| Update helper | `fuzevpn_update` target | Validated package handoff and portable replacement |
| Installer and maintenance | `installer/` | WiX packages, installation checks and cleanup |

The interface ordinarily runs without administrator privileges. Installed mode
uses a Windows service for privileged work; portable mode starts the helper
through elevation. Native boundaries validate the installation or distribution
mode, callers and operation inputs. Runtime package signatures and architecture
checks are part of production distribution policy.

OpenVPN 3 Core is compiled into the GUI and broker. WireGuard's embeddable
service and official WireGuardNT runtime are loaded as separate libraries.
OpenVPN DCO driver files retain their vendor signatures. These boundaries are
technical design choices; each component's licence still applies, as described
in [LICENSING.md](../LICENSING.md).

Account secrets and VPN identity material use the native protected-storage
bridge. Preferences use application storage; they are not a substitute for
protected secret storage. Diagnostic reports and local traces have separate
bounded storage and consent rules.

## Browser account sign-in

The account dialog offers browser sign-in alongside the existing e-mail and
password form. `lib/core/browser_auth.dart` implements a temporary loopback
receiver following the native-app pattern in
[RFC 8252](https://www.rfc-editor.org/rfc/rfc8252) and the S256 proof in
[RFC 7636](https://www.rfc-editor.org/rfc/rfc7636). It binds exclusively to
`127.0.0.1` on an ephemeral unprivileged port before opening the default browser.
The callback path is `/auth/callback`; the receiver never listens on a LAN
interface. Each attempt has independent cryptographically random state and
PKCE verifier values.

The public client identifier is `fuzevpn-windows` for both architectures and
distribution modes. The browser opens
`https://app.fuzevpn.com/desktop/connect` with `client_id`, `redirect_uri`,
`state`, `code_challenge` and `code_challenge_method=S256`. The Web application
authenticates the account and requests its consent through the API's
`POST /v1/auth/desktop/authorize` route. Windows accepts one state-matching
callback, then calls the public `POST /v1/auth/desktop/token` route once with
`client_id`, `code`, `redirect_uri` and `code_verifier`. There is no embedded
client secret, Web cookie or bearer token in this exchange.

The resulting desktop session follows the same profile validation, protected
storage and account identity initialization as password sign-in. It is
independent of the Web session. This signs in the account; VPN access still
requires an eligible subscription. The temporary authorization flow lasts at
most ten minutes through receipt of the token. After a token arrives in time,
normal local finalization completes. Reopening the browser retains the same
attempt; cancellation, logout, expiry and application disposal invalidate late
responses. A lost one-use token response requires a new explicit attempt.

Diagnostics record fixed stages and error codes for listener creation, browser
opening, callback validation and token exchange. Authorization URLs, codes,
state, verifiers and session tokens are excluded from logs and reports. These
local trace references are carried in `windows.support.timeline`; the common
schema-1 diagnostic error vocabulary is unchanged.

Network protection is implemented with Windows networking facilities, including
Windows Filtering Platform. Tunnel and protection state are observed separately.
An unavailable native observation remains an unknown state; it is not evidence
that a tunnel has stopped or that protections have been released.

Most controller and widget tests use injected API, storage and bridge doubles.
Native tests exercise parsers, policies, state machines and boundary checks.
They are distinct from testing a signed package, Windows elevation, a driver or
a real VPN connection on a target machine.
