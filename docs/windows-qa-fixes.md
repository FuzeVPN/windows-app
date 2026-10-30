# Windows qualification fixes

Release 1.0.11 includes all source corrections below, including storage and
collection diagnostics and cleanup before updating from a disconnected UI.
The precise historical filesystem cause of the supplied 1.0.8 diagnostic remains
unverified; instrumentation improves the evidence for a new connection attempt.

## 1.0.15 qualification findings (28 October 2026)

These source corrections follow the 1.0.15 VM campaign (69/72 cells, three
initial portable exits). They are not in any signed package yet: the existing
1.0.15 and 1.0.16 builds predate them. No VM run has verified them.

### Silent exits after WireGuard key generation

`CreateIdentityForAccount` loaded `tunnel.dll` to call
`WireGuardGenerateKeypair`, then unloaded it with `FreeLibrary`. That DLL is a
Go c-shared runtime: its threads (sysmon wakes within 60 s), vectored
exception/continue handlers and power/console callbacks stay registered, and
Go also suppresses WER for the process. After the unload, the process dies
silently at the next exception or Go thread wake. The cause was established
from code and timing; no dump or exit code was captured.

- Portable: the first sign-in on a fresh profile creates the identity inside
  `fuzevpn_windows.exe`. The frontend vanished about 60 s later on 25H2, 26300
  and Tiny11, and also in 1.0.13. The relaunch reads the stored key, so it
  survives.
- Installed: on Tiny11 the service generated a key for the first OpenVPN
  connect after the upgrade. About 6 s later it died while handling that
  connect (SCM 7031, frontend `broker_unavailable` 109).

The GUI, service and portable engine now generate the key pair in-process
(`wireguard_keypair.h`): `BCryptGenRandom`, WireGuard clamping and OpenSSL
X25519, byte-identical to the Go export, with RFC 7748 known-answer tests.
Stored identities are unchanged. Only the dedicated
`--fuzevpn-wireguard-service` process still loads `tunnel.dll`; it is pinned
and never freed. `libcrypto` is linked explicitly into the GUI, service and
identity tests.

### Device binding `storage_error` (Tiny11 portable)

The failing step was the frontend's protected write of `current_device_id`
after a successful enrollment, not the tunnel. The diagnostics-store worker
pinned every ancestor directory with read-only sharing, so `MoveFileExW` into
`%LOCALAPPDATA%\FuzeVPN` could fail with a sharing violation. Ancestors now
allow write sharing but still refuse delete sharing, so they cannot be
renamed or swapped. The leaf stays strict.

Protected writes and deletes retry `ERROR_SHARING_VIOLATION`,
`ERROR_ACCESS_DENIED` and `ERROR_LOCK_VIOLATION` for at most about 310 ms, and
report a closed `secure_store_*` stage, the Windows error and the attempt
count. The UI reports a protected-storage failure, keeps the server device id
in memory, and offers a retry that keeps the kill switch armed. The exact
historical cause remains unproven.

### WireGuard handshake window

The first handshake was awaited for only 8 s, about two initiations. The last
(or only) endpoint candidate now gets 20 s; earlier candidates keep 8 s for
fast failover. The connection and broker deadlines are unchanged. Each
candidate writes a numeric `connection_attempt_snapshot`: stage, durations,
tx/rx, handshake and `stats_reads`. Why the FR exit did not answer is still
unknown: ask the API owners whether the 201 for a relocated peer can precede
the node update.

### Retry and OpenVPN pending operations

With the kill switch on, the issue card's Réessayer only disconnected.
Réessayer, including in the "Emplacement indisponible" dialog, now re-runs
the same connection without releasing WFP. It is hidden when a retry is unsafe.
The `openvpn_operation_pending` wait is a 45 s budget (at most 6 attempts,
Retry-After honoured, default 3 s) instead of three attempts (about 28 s).
The UI still offers no cancel during that wait.

### Diagnostics

- Sign-in traces `local_identity`.
- The handled `device_location_locked` 409 is traced locally under its own
  name; v1 report codes are unchanged.
- Uppercase operation breadcrumbs such as `importAndConnect_started` are no
  longer dropped by the broker writer.
- API address-cache invalidation from connectivity hints is deferred while a
  connection command runs.

Retest on the VMs:
- fresh portable sign-in, then stay idle at least 3 minutes;
- installed EXE with the WireGuard identity deleted or the current device
  revoked, then OpenVPN and WireGuard connects with protections ON;
- the WireGuard FR/DE OFF cells;
- an `openvpn_operation_pending` retry from the blocked state.

`tunnel.dll` must not be mapped in `fuzevpn_windows.exe` or `FuzeVPNService`.

## Actionable storage and partial-collection diagnostics (17 October 2026)

The 1.0.8 diagnostic `a83ddfb0-4059-47d3-a33c-22314f1bdd7c` isolates
WireGuard's protected configuration write but loses the failing operation and
Windows status. Its native collection is also unavailable without a reason.
Those missing observations cannot establish the historical filesystem cause.

Protected runtime-directory validation and atomic configuration writing now
return a fixed `wg_storage_<target>_<operation>` reference and `win32_error`.
Targets identify only fixed application directories, never user paths. Steps
distinguish known-folder lookup, directory creation/opening, metadata, redirects,
owner/ACL policy, temporary-file creation, write, flush, close and replacement.
Windows errors are captured before handles and temporary files are cleaned up.
An owner/ACL/redirect policy rejection explicitly reports `ERROR_ACCESS_DENIED`;
a short successful write reports `ERROR_WRITE_FAULT`. These are policy/status
classifications; API failures retain the error returned by Windows.

The broker preserves these structured details in connect/reconnect errors. The
application accepts only the closed storage-stage vocabulary and bounded
Windows codes into `windows.support.timeline`. The version-1 top-level error
catalogue remains unchanged. No configuration text, keys, paths, exception text
or arbitrary native details enter this export.

Native environment, runtime, service and log readers now fail independently.
A reader exception records `ERROR_UNHANDLED_EXCEPTION` as a collection failure
while other sources continue. Dart independently validates each returned
fragment and retains valid observations when another fragment is rejected.
Collection metadata distinguishes `read_failed`, `rejected`, `timeout` and
`unavailable`, rather than converting all failures to `unavailable`. Native
collection discarded counts refer to rejected/missing fragments; native-log
counts continue to refer to log records.

An isolated native regression substitutes filesystem APIs and verifies 16
failure scenarios, preservation through cleanup, handle release, rejected
unsafe paths/owners/ACLs, and the successful atomic-write path. Local-collector
tests inject failure into each of four readers. Flutter regressions verify
precise stages survive complete-report serialization, partial evidence remains
available, timeout classification is correct, and private fields cannot leak.

These source changes are not present in the existing signed 1.0.9/1.0.10
packages. They improve evidence for a new attempt on the affected Windows
machine; they do not repair or retrospectively explain its storage failure.

## Update installation while already disconnected (17 October 2026)

A Windows 10 x64 diagnostic from 1.0.8 shows a prepared download followed by
`update_preinstall_failed`, before the installer launch. The preinstall callback
starts an exclusive native cleanup operation in `disconnecting` state even when
the UI is already `disconnected`. The state machine previously rejected that
transition with a `StateError` before any cleanup request could run.

Allow the idempotent transition from `disconnected` to `disconnecting`. Native
disconnect and both protocols' tunnel/protection checks still run before the
installer or portable replacement is launched. Six regression scenarios cover
installed/portable updates with an idle native runtime, a retained native tunnel
behind a disconnected UI, and failed native cleanup. Existing signed packages
1.0.9 and 1.0.10 do not include this later source change.

The same diagnostic separately records `storage_failure` from WireGuard's
native `connect` after account access, local identity and API configuration all
succeeded. That branch fails while preparing/writing the protected WireGuard
configuration, before its tunnel service starts. The supplied report lacks the
native Windows error and local service/log evidence, so its precise filesystem
cause is not established. This state-machine correction does not repair that
storage failure. Do not relax directory ACL validation or network protections
based on the generic error alone.

## Update compatibility found on 15 October 2026

The published 1.0.9 EXEs have correct versions, publisher signatures and hashes,
but WiX's version text was encoded as binary. `VerQueryValueW` returns 16 for
the ProductName size instead of 8 UTF-16 characters. The updater in every
published tag 1.0.6--1.0.8 rejects it as `update_package_version_mismatch`.
The exact `ReadVersion` implementation is identical in those tags. New 1.0.10
installers normalize the resource headers before signing, retaining that old
client contract. The client verification is not weakened. Existing public
1.0.9 files must remain unchanged at their versioned URLs.

Separately, the live update service returns a weak ETag in HTTP 200 and the same
opaque value as a strong ETag in HTTP 304. Older clients compare full strings
and report `update_manifest_invalid`. The new client uses weak ETag comparison;
already-installed clients additionally need a compatible HTTP response from
the API/CDN. A server handoff report records reproduction and proposes always
returning the full HTTP 200 manifest with `no-store, no-transform` and no ETag
or conditional 304 for this endpoint. Package metadata repair alone does not
resolve this HTTP issue in older clients.

The 12 October 2026 qualification of 1.0.8 confirmed two issues. The other
observations (unavailable ARM test environment, inconclusive reconnect OFF and
initial portable frontend disappearance) do not establish additional product
defects. This change addresses the startup recovery path in source. The Store
catalogue correction is a separate Partner Center operation performed by the
publisher.

## WIN-STARTUP-01: delayed service at Windows logon

The installer configures `FuzeVPNService` for delayed automatic startup. The
frontend originally retried an unknown native state after 250 ms, 1 s and 2 s,
then stopped. Even a subsequent successful verification deliberately did not
resume the requested launch connection. This can strand the automatically
launched frontend before the service's authenticated named pipe becomes ready.
The archived 25H2 run did not capture the original failing IPC transaction;
the precise timing of that historical failure remains unverified.

For a startup `broker_unavailable` failure, the frontend now performs bounded
passive observations for approximately five minutes of retry delays. Every
attempt uses the existing native authentication and status checks. It does not
start/install a service, release filters or replace an existing tunnel during
verification. Other kinds of unknown status keep the original three retries.

If launch auto-connect was already enabled with a saved session, successful
verification resumes that one launch request after both tunnels and their
filters are confirmed absent, the account is validated and locations are loaded.
OpenVPN availability is refreshed too. Account validation delayed by boot-time
network availability has its own bounded retries. A disabled option, explicit
verification/connection action, account sign-out or disposal cancels the deferred
request. A live tunnel, retained filters or another Windows user's ownership
prevents it from creating a replacement connection. Merely enabling the option
later does not create a deferred launch request.

Synthetic Flutter regressions cover service availability beyond two minutes,
WireGuard/OpenVPN, auto-connect OFF, cancellation, retained native state, account
availability and the retry limit. Existing passive account/state verification
regressions still apply. These tests do not reproduce a Windows reboot or
establish a new VM/hardware qualification.

Retest a newly versioned signed MSI on 25H2: enable launch with Windows and
auto-connect, select a location, reboot, and observe without relaunching the
frontend. Capture service start time and authenticated IPC status, frontend
start time, adapters, routes and public IP. Repeat with a delayed service,
auto-connect OFF and an explicit cancellation. Test Insider/tiny11 separately;
ARM64 execution still needs a usable physical test device.

## WIN-STORE-01: MSI catalogue switches

The public Store manifest for `XPFM3116NCW2W8`, inspected on 13 October 2026,
publishes the following for both 1.0.8 MSI architectures:

| Architecture | Installer | Current silent switches | Required switches |
| --- | --- | --- | --- |
| x64 | `FuzeVPN-1.0.8-x64.msi` | `/install /quiet /norestart` | `/quiet /norestart` |
| ARM64 | `FuzeVPN-1.0.8-arm64.msi` | `/install /quiet /norestart` | `/quiet /norestart` |

WinGet's [MSI argument parser](https://github.com/microsoft/winget-cli/blob/master/src/AppInstallerCommonCore/MsiExecArguments.cpp)
rejects `/install` before invoking the Windows Installer API. This is consistent
with the observed `0x8A15004A`. `/install` belongs to the EXE Burn command line;
it is not an extra switch for a Store MSI. Do not add `/i`, an MSI path, or
`msiexec.exe` to that catalogue field either: Store/WinGet supplies the package.
The EXE help text and its command line remain valid.

In Partner Center, edit the silent installation parameters for both MSI package
entries to `/quiet /norestart` and submit that correction. Keep the current MSI
URLs and hashes when correcting only the catalogue. Microsoft requires an
[unchanged binary at each submitted versioned URL](https://learn.microsoft.com/en-us/windows/apps/publish/publish-your-app/msi/app-package-requirements).
An application code fix needs a new version, signed packages and new URLs; do
not replace public 1.0.8 binaries with local rebuilds.

After the catalogue update is published, verify it from the repository:

```powershell
.\tools\check-windows-store-manifest.ps1
```

This read-only check covers every returned locale entry for both architectures.
It does not install or launch anything. `-ManifestPath` reads a saved response;
`-OutputPath` saves a compact verification report. A local corrected fixture is
not evidence that Partner Center or the live Store has changed.

Then retest the real Store install button and the WinGet `msstore` route on
25H2 and Insider. Capture the selected manifest, actual installer arguments,
exit code, installed product/version and successful execution. Until those
steps pass, the Store correction remains pending external application and retest.
