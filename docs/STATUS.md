# Status

What works, how it was checked, and what is still open. Updated with every milestone.

## Summary

| Area | State |
|---|---|
| Core (classification, process tree, attribution, rules, ask mode) | Built and tested on macOS 27 (Swift 6.4) and Linux |
| Store, IPC, daemon, CLI, eslogger (monitor-only) backend | Built and tested on macOS 27; on-device acceptance pending |
| Native Endpoint Security source and blocking | Compiles against the macOS 27 SDK; runs only in a SIP-disabled VM until Apple grants the entitlement |
| Menu bar app (SwiftUI) and system extension | Compile and type-check against the macOS 27 SDK; bundles assemble and sign ad hoc; on-device checks pending |
| Packaging (Developer ID, notarization) | Scripts written; needs an Apple Developer account and the Endpoint Security entitlement |

## Tests

`scripts/dev/sc-build.sh test` on macOS 27.0.1 (Xcode 27.0):

| Bundle | Executed | Failures | Skipped |
|---|---|---|---|
| WhoReadCoreTests | 311 | 0 | 0 |
| WhoReadStoreTests | 17 | 0 | 0 |
| WhoReadEngineTests | 292 | 0 | 22 |
| WhoReadUIModelTests | 42 | 0 | 0 |

The skipped tests bind a Unix socket, which a sandboxed shell does not allow; they run in CI
(`.github/workflows/ci.yml`) and in the VM. Tool self-tests: `scripts/dev/sc-app-test.sh`
(app bundles), `scripts/vm/selftest.sh` (VM job runner), `scripts/dev/es-typecheck/check-stub.sh`
(the Linux Endpoint Security stub against the real SDK).

## Security reviews

Three review rounds covered coverage and evasion (paths, links, moves, process tree, attribution),
the privilege model, denial of service, privacy, macOS API use and packaging. Every finding was
checked by a second reviewer, fixed with a regression test and re-checked. Regression tests name
the finding they cover (for example `files-1`, `privacy-3`).

Highlights of the latest round:
- a moved, cloned or planted folder is judged by every category it can hold;
- unknown or truncated process ancestry never counts as started by launchd or as all-Apple;
- on macOS 27 the Endpoint Security client runs in fail-closed mode: a missed deadline, or an
  authorization the kernel drops from a full queue, is denied and the daemon is not killed;
- permission, owner, ACL and mount changes on monitored paths are authorization events;
- names and paths shown in alerts, questions and CLI output are sanitized;
- recorded history is served only to root and the signed app;
- the data, log and kill-switch directories must be root-owned and closed to others.

## Open

- On-device acceptance in a SIP-disabled VM (`scripts/vm/README.md`): monitor-only acceptance,
  enforcement acceptance, CPU overhead, the real ask-mode hold budget, and the pending checks in
  [RESEARCH.md](RESEARCH.md).
- The app on a device: onboarding, menu bar, every tab, question notifications, kill switches,
  both languages.
- The Endpoint Security entitlement from Apple, then a Developer ID build
  ([DISTRIBUTION.md](DISTRIBUTION.md)). Until then blocking works only in a SIP-disabled VM; the
  monitor-only backend works on a normal Mac.
