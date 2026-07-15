# Payloader Privacy Policy

Payloader is a self-hosted security knowledge and encoding workspace. Payloader does not collect telemetry, analytics, advertising identifiers, or automatic crash reports. The application displays security testing commands as reference content and does not execute those commands automatically.

## Network Activity

Payloader makes the following bounded network requests:

- The self-hosted server checks the fixed public Payloader repository on the GitHub API for release and source updates. The first check starts after application startup and subsequent checks use the configured interval. Operators can disable automatic checks with `PAYLOADER_UPDATE_CHECK_DISABLED=true` and can leave `PAYLOADER_GITHUB_TOKEN` unset to use anonymous GitHub access.
- When an operator generates a client for a platform that needs an official shell, the server can download the fixed shell manifest and matching artifacts from the official GitHub Release. Operators can disable remote shell access with `PAYLOADER_CLIENT_SHELLS_REMOTE_DISABLED=true` or configure a local read-only shell directory.
- GitHub project and Xeye links open only after a user selects the corresponding link. Opening an external site sends ordinary browser request data, such as the IP address and user-agent, to that site under the site's own policy.
- Package installation and release builds can download declared dependencies from npm, Electron, GitHub, and configured trusted mirrors. These are operator or maintainer build-time actions, not end-user telemetry.

The packaged Electron renderer is offline by default. Its content security policy permits only the internal `payloader://app` origin, it rejects renderer network requests, and it opens only the fixed GitHub project and Xeye HTTPS links after user interaction.

## Stored Data

- The server stores public content, administrator account hashes, configuration records, custom content, and build metadata in the configured SQLite data directory.
- Administrator JWT signing material, backups, uploads, caches, and generated clients remain in the configured server data directory. They are not included in public client data packages.
- The administrator access token is stored in browser `sessionStorage` for the current tab and is removed when the session is cleared or the user logs out.
- Theme and navigation preferences can be stored in browser `localStorage`.
- A reverse proxy or hosting provider can create access logs independently of Payloader. Deployment operators control those logs and their retention.

Payloader does not send stored administrator credentials, JWT secrets, SQLite databases, backups, private uploads, or environment variables to the client build process or the public repository.

## Retention and Deletion

Deployment operators control retention. The administration interface supports content export, reset previews, and backup-backed resets. To remove server data, stop Payloader and delete the configured `PAYLOADER_DATA_DIR` after retaining any required backup.

The Windows client includes a standard uninstaller and can be removed through Windows Settings. Linux AppImages can be removed by deleting the downloaded file. macOS applications can be removed from the selected installation directory. Operating systems may retain ordinary per-user application cache files, which users can delete from their profile after uninstalling.

## External Services

- GitHub API and Releases: [GitHub Privacy Statement](https://docs.github.com/en/site-policy/privacy-policies/github-general-privacy-statement)
- Xeye: [https://xss.icu/](https://xss.icu/), opened only on user request
- SignPath signing service: used only by maintainers during release signing; end-user application data is not submitted for signing

Privacy questions and corrections can be reported through [Payloader issues](https://github.com/3516634930/Payloader/issues).
