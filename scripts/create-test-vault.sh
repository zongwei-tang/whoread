#!/bin/bash
# Creates ~/WhoReadTestVault with FAKE secrets. Every automated test reads/writes only here.
# The SSH key is a throwaway generated on the spot so `ssh-keygen -y -f` works (M5 owner test);
# it is never added to any account. AWS values are AWS's documented example credentials.
set -euo pipefail
VAULT="${WHOREAD_TEST_VAULT:-$HOME/WhoReadTestVault}"
mkdir -p "$VAULT/ssh" "$VAULT/aws" "$VAULT/notes" "$VAULT/project"
chmod 700 "$VAULT" "$VAULT/ssh"
if [ ! -f "$VAULT/ssh/id_ed25519" ]; then
  ssh-keygen -q -t ed25519 -N "" -C "whoread-test-key-not-used-anywhere" -f "$VAULT/ssh/id_ed25519"
fi
cat > "$VAULT/ssh/config" <<'CFG'
# WhoRead test vault: fake SSH config
Host example-test-host
  HostName 192.0.2.10
  User nobody
CFG
cat > "$VAULT/aws/credentials" <<'CFG'
# WhoRead test vault: AWS documentation example values, not real credentials
[default]
aws_access_key_id = AKIAIOSFODNN7EXAMPLE
aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
CFG
echo "FAKE_TOKEN=whoread-test-not-a-secret" > "$VAULT/project/.env"
echo "todo: nothing real here" > "$VAULT/notes/todo.txt"
echo "old" > "$VAULT/notes/old.txt"
echo "Test vault ready at $VAULT"
ls -la "$VAULT" "$VAULT/ssh"
