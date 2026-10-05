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

Network protection is implemented with Windows networking facilities, including
Windows Filtering Platform. Tunnel and protection state are observed separately.
An unavailable native observation remains an unknown state; it is not evidence
that a tunnel has stopped or that protections have been released.

Most controller and widget tests use injected API, storage and bridge doubles.
Native tests exercise parsers, policies, state machines and boundary checks.
They are distinct from testing a signed package, Windows elevation, a driver or
a real VPN connection on a target machine.
