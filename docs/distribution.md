# Distribution

FuzeVPN supports installed and portable Windows distributions for x64 and ARM64.
The public source snapshot is version 1.0.6. Its six signed packages are
published unchanged: one EXE, one MSI and one portable ZIP per architecture.

## Package behaviour

The EXE bootstrapper wraps the MSI installation and uses source-built WiX Burn
components. Installed mode registers the privileged service and uses the
installation's protected files. Portable mode keeps its runtime together in
the extracted application folder and uses an elevated helper when required.
Extract the complete portable ZIP before launching the app.

Build scripts expose development and production distribution policies.
`-DevTest` is for local unsigned validation. Production packages require an
appropriate code-signing certificate, timestamped signatures and package
verification. Certificates and signing credentials are not supplied by this
repository or used by public CI. A locally rebuilt binary will not reproduce
the publisher's signatures or the byte-for-byte checksum of a signed release.

## Release contents

Keep all six packages and their checksum files. Installer releases must also
provide `WiX-corresponding-source.zip` and `WiX-MS-RL.txt`. Every runtime package
must retain the notices, licences, driver files and source archives required
by [LICENSING.md](../LICENSING.md) and
[THIRD_PARTY_NOTICES.md](../THIRD_PARTY_NOTICES.md).

The package source snapshot and its licence must remain available from the
matching release tag. Verify architecture, signatures, checksums and package
contents before uploading. Native ARM64 execution requires an ARM64 Windows
machine; cross-compilation and signature checks do not replace that validation.

## Updates

Update discovery is separated from installation. Metadata is validated for its
version, architecture, distribution mode, HTTPS URL, digest and publisher.
Installed automatic updates support the signed EXE installer. A newer valid
MSI-only update requires manual installation; an older or equal MSI is not an
available update. Portable updates use the matching ZIP archive.

Prepared updates are checked again before handoff. Do not bypass validation,
edit a signed artifact after checksums are generated, or serve an installer
manifest for a portable package. Portable replacement requires a filesystem
with persistent access-control lists, such as NTFS or ReFS; on other supported
storage, close the app and replace the extracted folder manually.

Public release publication and the live update API are separate actions.
Uploading files to GitHub does not change the hosted update service.
