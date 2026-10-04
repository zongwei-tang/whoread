# eslogger fixtures

| Directory | Origin | Shape |
|---|---|---|
| `schema-v1-msgv7/` | **Synthetic** (`scripts/dev/gen_fixtures.py`) | Same keys, types and key order as genuine eslogger output with message version 7 (macOS 13.3+, 2023), unescaped `/`. |
| `schema-v1-msgv10/` | **Synthetic** | Shape of genuine macOS 26 output (message version 10): single line, `\/`-escaped slashes, hash-ordered keys, `cs_validation_category`. |
| `schema-v2-synthetic/` | **Synthetic** | Hypothetical future `schema_version` 2: missing `original_ppid`/`start_time`, unknown fields, junk lines. Tests tolerance only. |
| `captured/macos-<version>/` | **Real**, from `scripts/capture-fixture.sh` on your Mac, sanitized by `whoread fixture sanitize` | Added once you run the M0 capture. `captured/raw/` is gitignored. |

The synthetic files mirror real samples collected from public sources. Their provenance is in
`docs/research/eslogger-libproc-packaging.md` §A3:
- genuine macOS 26 single-line output (exec/fork/exit/unlink);
- genuine 2023 message-v7 test fixtures (open, close, rename both destination types, clone,
  copyfile, link, unlink, truncate, create, readdir).

No third-party sample is copied verbatim into this repository. Paths, pids and hashes are ours.

All three synthetic files encode the same scenario, the M2 acceptance test against
`/Users/alice/WhoReadTestVault`:
- Terminal → zsh → cat, python3 and node reading the fake key and credentials;
- Claude Code (npm) → zsh → cat;
- a background cat reparented to launchd;
- Spotlight (`mdworker_shared`) reading a note;
- rename, clone, copyfile and link out of the vault; truncate, unlink, a modified close, a
  firmlinked path spelling, and a rename onto a vault file.

The tests require every shape to produce identical records.
