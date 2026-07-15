# SignPath Foundation Onboarding

This document is the maintainer handoff for the free open-source signing application. It does not contain credentials and does not claim that SignPath has approved the project.

## Application Record

- Project: Payloader
- Public source: https://github.com/3516634930/Payloader
- Project website: https://github.com/3516634930/Payloader
- License: AGPL-3.0-only
- Maintainer: https://github.com/3516634930
- Code signing policy: https://github.com/3516634930/Payloader/blob/main/CODE_SIGNING_POLICY.md
- Privacy policy: https://github.com/3516634930/Payloader/blob/main/PRIVACY.md
- Build system: GitHub-hosted GitHub Actions runners
- Windows packages: NSIS installers for x64, arm64, and ia32
- Function: a self-hosted security knowledge, payload reference, and encoding workspace for authorized testing. The packaged client displays and copies reference content; it does not automatically execute the documented commands.

The application must accurately disclose the security-testing content. SignPath Foundation decides whether the project meets its no-malware and no-potentially-unwanted-program requirements.

## Account Requirements

Before applying or approving a release:

1. Enable multi-factor authentication on the maintainer's GitHub account.
2. Apply at https://signpath.org/apply using the public repository and policy links above.
3. Install the SignPath GitHub App for the public repository when requested by SignPath.
4. Enable multi-factor authentication on the SignPath account.
5. Keep every release signing policy configured for manual approval.

Do not accept a configuration that signs locally supplied binaries, self-hosted-runner output, or artifacts that cannot be traced to the public workflow run.

## Repository Configuration

After SignPath creates the project, configure these values in the public GitHub repository. The API token is an encrypted secret; identifiers and slugs can be repository variables unless SignPath classifies them as secrets.

| Name | Storage | Purpose |
| --- | --- | --- |
| `SIGNPATH_API_TOKEN` | Actions secret | Submit signing requests for the approved project only |
| `SIGNPATH_ORGANIZATION_ID` | Actions variable | SignPath organization identifier |
| `SIGNPATH_PROJECT_SLUG` | Actions variable | Payloader project slug |
| `SIGNPATH_SIGNING_POLICY_SLUG` | Actions variable | Manual-approval release policy |
| `SIGNPATH_APP_ARTIFACT_CONFIGURATION_SLUG` | Actions variable | Sign prepared application executables before packaging |
| `SIGNPATH_INSTALLER_ARTIFACT_CONFIGURATION_SLUG` | Actions variable | Sign completed NSIS installer executables |

The workflow must pin `SignPath/github-action-submit-signing-request` to a reviewed immutable commit. It must use the workflow artifact ID produced by `actions/upload-artifact`, wait for completion, and download the signed result into a new directory instead of overwriting the unsigned input in place.

## Required Two-Stage Build

NSIS installers are PE files but are not a SignPath deep-signing container. Signing only the outer installer would leave the packaged application executable unsigned. Payloader therefore requires two signing requests per Windows release workflow:

1. Build a prepared application directory for each Windows architecture without creating the installer.
2. Upload a ZIP containing the prepared application directories as a GitHub Actions artifact.
3. Submit the prepared application artifact to the application artifact configuration. An Approver performs manual approval.
4. Download the signed application artifact and verify each project-owned executable with `Get-AuthenticodeSignature`.
5. Build each NSIS installer from the corresponding signed prepared application directory without modifying the signed executable.
6. Build the backend Windows shell transport from the same signed application directory.
7. Upload the completed installers as another GitHub Actions artifact.
8. Submit the installer artifact to the installer artifact configuration. An Approver performs manual approval.
9. Download the signed installers, verify all installer and shell executable signatures, regenerate checksums, and publish only those verified files.

The application artifact configuration should sign only Payloader-owned PE files and verify, not replace, signatures on redistributed upstream binaries. The installer artifact configuration should sign the three `Payloader-Client-Setup-<version>-<arch>.exe` files.

## Acceptance Checks

The first signed release is ready only when all checks pass:

- The signing request links to the expected public commit and GitHub-hosted workflow run.
- Both signing requests show the expected manual Approver.
- `Get-AuthenticodeSignature` returns `Valid` for x64, arm64, and ia32 installers.
- The main Payloader executable extracted from each Windows shell returns `Valid`.
- The installed main executable returns `Valid` after a clean x64 installation.
- Product name and version metadata match `Payloader` and `package.json`.
- `SHA256SUMS.txt` is regenerated after signing and matches every published artifact.
- The unsigned inputs and signed outputs have separate artifact names and audit records.
- The GitHub Release contains only the signed Windows installers and the verified signed Windows shell transports.

Microsoft SmartScreen reputation is evaluated separately from signature validity. The first signed files can still receive an unknown-reputation warning until the publisher or file hash accumulates positive reputation.
