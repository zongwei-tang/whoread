# Distribution

WhoRead ships as a Developer ID–signed, notarized app that embeds an Endpoint Security system
extension. Everything on this page needs **your** Apple Developer account. Apple quotes are in
[`research/packaging-details.md`](research/packaging-details.md).

## 1. Prerequisites

- An Apple Developer Program membership. For an organization, the **Account Holder** has to
  submit capability requests.
- Two bundle IDs (App IDs), for example:
  - `com.yourname.whoread`: the app; capability **System Extension** (gives
    `com.apple.developer.system-extension.install`);
  - `com.yourname.whoread.extension`: the extension; needs **Endpoint Security**
    (`com.apple.developer.endpoint-security.client`).

  The extension ID is prefixed with the app ID. Set the same values in `Xcode/Local.xcconfig`
  (`BUNDLE_ID_PREFIX`, `DEVELOPMENT_TEAM`).
- Certificates: **Developer ID Application** (signing) and Xcode for archiving.

## 2. Request the Endpoint Security entitlement

`com.apple.developer.endpoint-security.client` is a restricted entitlement. Apple grants it per
team after review. Sources disagree on the exact path (see RESEARCH.md #12), so check both:

1. **Capability Requests** (the brief's path). Certificates, Identifiers & Profiles → Identifiers →
   select the extension's App ID → **Capability Requests** tab → find Endpoint Security →
   **Request** → submit the form. Requires the Account Holder role.
2. **System Extensions request form.** Apple's Endpoint Security docs say to request the
   entitlement via <https://developer.apple.com/system-extensions/> → "Request an Entitlement",
   which leads to <https://developer.apple.com/contact/request/system-extension/>.

What to write in the request:
- What WhoRead does: local monitoring of access to sensitive files, optional user-defined
  blocking.
- Which events it uses: NOTIFY and AUTH for open, rename, clone, copyfile, link, unlink, truncate,
  exchangedata, and NOTIFY fork/exec/exit.
- That it uses inverted target-path muting, so only monitored prefixes are delivered.
- That nothing leaves the machine.

While the request is in review you can develop in a SIP-disabled VM (DEVELOPMENT.md).

## 3. Provisioning profiles

Once Apple grants the entitlement, create **Developer ID** provisioning profiles:
- app profile: System Extension capability;
- extension profile: Endpoint Security.

Put their names into `scripts/release/ExportOptions.plist`, created from the template.

Info.plist keys, already in `Xcode/project.yml`:
- extension: `NSEndpointSecurityMachServiceName` (= `$(DEVELOPMENT_TEAM).<extension id>.xpc`;
  documented only in the `EndpointSecurity(7)` man page), `NSSystemExtensionUsageDescription`
  (localized in `Extension/*.lproj/InfoPlist.strings`), `CFBundlePackageType` =
  `$(PRODUCT_BUNDLE_PACKAGE_TYPE)` (XcodeGen does not set it for system extensions);
- `WhoReadClientRequirement` / `WhoReadAppRequirement`: the code-signing requirements the
  extension enforces on XPC clients (team-pinned).

The `whoread` CLI is embedded as `WhoRead.app/Contents/Helpers/whoread` and signed with the same
team, so it satisfies `WhoReadClientRequirement`; a self-built CLI does not. It has no restricted
entitlements and needs no provisioning profile.

## 4. Build, notarize, staple

```bash
xcrun notarytool store-credentials whoread-notary --apple-id you@example.com --team-id ABCDE12345
scripts/release/release.sh whoread-notary
```

`release.sh`:
1. archives the app;
2. exports it with Developer ID;
3. checks signatures, that the embedded extension carries the ES entitlement, and that the
   embedded CLI and the app satisfy the extension's client and app requirements;
4. zips it with `ditto`, then `notarytool submit --wait`, `stapler staple` the app;
5. builds a DMG, signs, notarizes and staples it.

Output: `build/release/WhoRead.dmg`.

Hardened Runtime is on for all targets (`ENABLE_HARDENED_RUNTIME`), as notarization requires.

## 5. What the user does

0. Developers only: if the dev LaunchDaemon is installed, remove it first
   (`sudo scripts/uninstall-dev-daemon.sh`). Only one daemon may use
   `/Library/Application Support/WhoRead`; whichever starts second refuses to run.
1. Drag WhoRead to **/Applications** (system extensions only activate from there) and open it.
2. Onboarding → **Install extension** → macOS asks for approval in System Settings → General →
   Login Items & Extensions.
3. Grant **Full Disk Access** to WhoRead's extension (onboarding opens the right pane;
   macOS 13+ deep link `x-apple.systempreferences:com.apple.settings.PrivacySecurity.extension?Privacy_AllFiles`).
4. Put the CLI on `PATH` (optional, but it carries the `sudo whoread enforcement off` kill
   switch):
   ```bash
   sudo mkdir -p /usr/local/bin
   sudo ln -sf /Applications/WhoRead.app/Contents/Helpers/whoread /usr/local/bin/whoread
   ```
5. The extension pins owner apps to the team IDs `codesign -dv` reports on this Mac, in memory,
   at every start. To see what it finds (nothing is written):
   ```bash
   sudo whoread catalog resolve-owners
   ```
6. WhoRead learns for 7 days, then alerts only on unusual access. Blocking stays off until the
   user turns on enforcement and marks rules as Enforce.

The extension logs to `/Library/Logs/WhoRead/extension.log` (root only).

## 6. Uninstall

```bash
scripts/release/uninstall.sh [--purge]
```
It first creates the kill-switch file, so nothing stays blocked. If `systemextensionsctl list`
shows the extension, it runs `WhoRead --uninstall-extension`, which submits an
`OSSystemExtensionRequest` deactivation that the user confirms. If that fails or is cancelled,
the script stops and keeps the app, since an extension without its app has no UI to turn it off.
It also stops, keeping the kill switch and the data, when a WhoRead extension is still active
that it cannot deactivate, for example because the app is no longer in `/Applications`: put the
app back and rerun.
Otherwise it removes the dev LaunchDaemon if present, the `/usr/local/bin/whoread` link, the app
and, with `--purge`, `/Library/Application Support/WhoRead` and the logs.
`systemextensionsctl uninstall` is not used because it requires SIP to be disabled.
