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

## 4. Build, notarize, staple

```bash
xcrun notarytool store-credentials whoread-notary --apple-id you@example.com --team-id ABCDE12345
scripts/release/release.sh whoread-notary
```

`release.sh`:
1. archives the app;
2. exports it with Developer ID;
3. checks signatures and that the embedded extension carries the ES entitlement;
4. zips it with `ditto`, then `notarytool submit --wait`, `stapler staple` the app;
5. builds a DMG, signs, notarizes and staples it.

Output: `build/release/WhoRead.dmg`.

Hardened Runtime is on for all targets (`ENABLE_HARDENED_RUNTIME`), as notarization requires.

## 5. What the user does

1. Drag WhoRead to **/Applications** (system extensions only activate from there) and open it.
2. Onboarding → **Install extension** → macOS asks for approval in System Settings → General →
   Login Items & Extensions.
3. Grant **Full Disk Access** to WhoRead's extension (onboarding opens the right pane;
   macOS 13+ deep link `x-apple.systempreferences:com.apple.settings.PrivacySecurity.extension?Privacy_AllFiles`).
4. WhoRead learns for 7 days, then alerts only on unusual access. Blocking stays off until the
   user turns on enforcement and marks rules as Enforce.

## 6. Uninstall

```bash
scripts/release/uninstall.sh [--purge]
```
It runs `WhoRead --uninstall-extension`, which submits an `OSSystemExtensionRequest`
deactivation that the user confirms, removes the app and, with `--purge`, deletes
`/Library/Application Support/WhoRead`. `systemextensionsctl uninstall` is not used because it
requires SIP to be disabled.
