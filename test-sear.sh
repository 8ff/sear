#!/bin/sh
# ═══════════════════════════════════════════════════════════════════════
# test-sear.sh — comprehensive tests for sear
#
# Runs without a YubiKey using ephemeral ed25519 + age keys.
# Tests all commands: sign, verify, encrypt, decrypt, keygen errors.
# ═══════════════════════════════════════════════════════════════════════
set -eu

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
SEAR="${SCRIPT_DIR}/sear"
WORKDIR="$(mktemp -d)"
PASS=0
FAIL=0
TOTAL=0

cleanup() { rm -rf "$WORKDIR"; }
trap cleanup EXIT

green()  { printf '\033[1;32m%s\033[0m\n' "$1"; }
red()    { printf '\033[1;31m%s\033[0m\n' "$1"; }
header() { printf '\n\033[1;36m━━ %s ━━\033[0m\n' "$1"; }

assert_ok() {
    TOTAL=$((TOTAL + 1))
    if eval "$1" >/dev/null 2>&1; then
        green "  PASS: $2"; PASS=$((PASS + 1))
    else
        red   "  FAIL: $2"; FAIL=$((FAIL + 1))
    fi
}

assert_fail() {
    TOTAL=$((TOTAL + 1))
    if eval "$1" >/dev/null 2>&1; then
        red   "  FAIL: $2 (expected failure)"; FAIL=$((FAIL + 1))
    else
        green "  PASS: $2"; PASS=$((PASS + 1))
    fi
}

assert_contains() {
    TOTAL=$((TOTAL + 1))
    OUTPUT=$(eval "$1" 2>&1) || true
    if printf '%s' "$OUTPUT" | grep -q "$2"; then
        green "  PASS: $3"; PASS=$((PASS + 1))
    else
        red   "  FAIL: $3 (output did not contain '$2')"; FAIL=$((FAIL + 1))
    fi
}

assert_stdout() {
    TOTAL=$((TOTAL + 1))
    OUTPUT=$(eval "$1" 2>/dev/null) || true
    if printf '%s' "$OUTPUT" | grep -q "$2"; then
        green "  PASS: $3"; PASS=$((PASS + 1))
    else
        red   "  FAIL: $3 (stdout did not contain '$2')"; FAIL=$((FAIL + 1))
    fi
}

# ── Setup ─────────────────────────────────────────────────────────────
header "Setup: generating ephemeral test keys"

# SSH keys (Alice, Bob, Eve)
ssh-keygen -t ed25519 -f "$WORKDIR/alice" -N "" -q -C "alice@example.com"
ssh-keygen -t ed25519 -f "$WORKDIR/bob" -N "" -q -C "bob@example.com"
ssh-keygen -t ed25519 -f "$WORKDIR/eve" -N "" -q -C "eve@evil.com"
printf 'SSH keys: alice, bob, eve\n'

# Age keys
age-keygen -o "$WORKDIR/age_alice.txt" 2>/dev/null
AGE_ALICE_RCPT=$(grep "public key:" "$WORKDIR/age_alice.txt" | awk '{print $NF}')
age-keygen -o "$WORKDIR/age_bob.txt" 2>/dev/null
AGE_BOB_RCPT=$(grep "public key:" "$WORKDIR/age_bob.txt" | awk '{print $NF}')
printf 'Age keys: alice (%s), bob (%s)\n' "$AGE_ALICE_RCPT" "$AGE_BOB_RCPT"

# Test payload
cat > "$WORKDIR/payload.txt" <<'EOF'
#!/bin/sh
echo "legitimate deployment v2.1.0"
EOF

# ══════════════════════════════════════════════════════════════════════
# SECTION 1: HELP & VERSION
# ══════════════════════════════════════════════════════════════════════

header "Test: help and version"

assert_ok "'$SEAR' help" "help exits 0"
assert_ok "'$SEAR' --help" "--help exits 0"
assert_ok "'$SEAR' -h" "-h exits 0"
assert_ok "'$SEAR' version" "version exits 0"
assert_ok "'$SEAR' --version" "--version exits 0"
assert_ok "'$SEAR' -V" "-V exits 0"
assert_contains "'$SEAR' version" "sear" "version output contains 'sear'"
assert_fail "'$SEAR'" "no args exits 1"
assert_fail "'$SEAR' bogus" "unknown command exits 1"

# Subcommand help
assert_ok "'$SEAR' sign -h" "sign -h exits 0"
assert_ok "'$SEAR' verify --help" "verify --help exits 0"
assert_ok "'$SEAR' encrypt -h" "encrypt -h exits 0"
assert_ok "'$SEAR' decrypt --help" "decrypt --help exits 0"

# Help topics
assert_ok "'$SEAR' help sign" "help sign exits 0"
assert_ok "'$SEAR' help verify" "help verify exits 0"
assert_ok "'$SEAR' help seal" "help seal exits 0"
assert_ok "'$SEAR' help unseal" "help unseal exits 0"
assert_ok "'$SEAR' help encrypt" "help encrypt exits 0"
assert_ok "'$SEAR' help decrypt" "help decrypt exits 0"
assert_ok "'$SEAR' help keygen" "help keygen exits 0"
assert_ok "'$SEAR' help age-keygen" "help age-keygen exits 0"
assert_ok "'$SEAR' help age-identity" "help age-identity exits 0"
assert_ok "'$SEAR' help age-list" "help age-list exits 0"
assert_ok "'$SEAR' help setup" "help setup exits 0"
assert_ok "'$SEAR' help yubikey" "help yubikey exits 0"
assert_fail "'$SEAR' help bogus" "help bogus exits 1"

# Per-command help shows command-specific content, not full help
assert_contains "'$SEAR' sign -h" "sear sign" "sign -h shows sign-specific help"
assert_contains "'$SEAR' help sign" "sear sign" "help sign shows sign-specific help"

# keygen/age-keygen with no args exits 1
assert_fail "'$SEAR' keygen" "keygen no args exits 1"
# age-keygen requires age-plugin-yubikey
if command -v age-plugin-yubikey >/dev/null 2>&1; then
    assert_contains "'$SEAR' age-keygen" "Generating age key" "age-keygen no args attempts keygen"
else
    printf '  SKIP: age-keygen (age-plugin-yubikey not installed)\n'
fi

# ══════════════════════════════════════════════════════════════════════
# SECTION 2: SIGNING
# ══════════════════════════════════════════════════════════════════════

header "Test: sign a file"

"$SEAR" sign -k "$WORKDIR/alice" "$WORKDIR/payload.txt" 2>/dev/null
assert_ok "[ -f '$WORKDIR/payload.txt.sig' ]" "signature file created"

header "Test: sign multiple files"

echo "file two" > "$WORKDIR/second.txt"
echo "file three" > "$WORKDIR/third.txt"
"$SEAR" sign -k "$WORKDIR/alice" "$WORKDIR/second.txt" "$WORKDIR/third.txt" 2>/dev/null
assert_ok "[ -f '$WORKDIR/second.txt.sig' ] && [ -f '$WORKDIR/third.txt.sig' ]" \
    "both signature files created"

header "Test: sign with -o custom output"

"$SEAR" sign -k "$WORKDIR/alice" -o "$WORKDIR/custom.sig" "$WORKDIR/payload.txt" 2>/dev/null
assert_ok "[ -f '$WORKDIR/custom.sig' ]" "custom output signature created"

header "Test: sign -o with multiple files fails"

assert_fail "'$SEAR' sign -k '$WORKDIR/alice' -o out.sig '$WORKDIR/second.txt' '$WORKDIR/third.txt'" \
    "-o with multiple files rejected"

header "Test: sign nonexistent file"

assert_fail "'$SEAR' sign -k '$WORKDIR/alice' '$WORKDIR/nope.txt'" \
    "sign fails on missing file"

header "Test: sign with no key configured"

assert_fail "'$SEAR' sign '$WORKDIR/payload.txt'" \
    "sign fails when default key missing"

header "Test: sign with no files"

assert_fail "'$SEAR' sign -k '$WORKDIR/alice'" \
    "sign fails when no files specified"

header "Test: sign overwrites existing .sig"

"$SEAR" sign -k "$WORKDIR/alice" "$WORKDIR/payload.txt" 2>/dev/null
"$SEAR" sign -k "$WORKDIR/alice" "$WORKDIR/payload.txt" 2>/dev/null
assert_ok "[ -f '$WORKDIR/payload.txt.sig' ]" "re-signing does not fail"

header "Test: sign with custom namespace"

"$SEAR" sign -k "$WORKDIR/alice" -n "production" "$WORKDIR/payload.txt" 2>/dev/null
assert_ok "[ -f '$WORKDIR/payload.txt.sig' ]" "sign with custom namespace"

header "Test: sign rejects empty namespace"

assert_fail "'$SEAR' sign -k '$WORKDIR/alice' -n '' '$WORKDIR/payload.txt'" \
    "empty namespace rejected"

header "Test: sign rejects namespace with spaces"

assert_fail "'$SEAR' sign -k '$WORKDIR/alice' -n 'has space' '$WORKDIR/payload.txt'" \
    "namespace with space rejected"

header "Test: sign stdout contains OK"

assert_stdout "'$SEAR' sign -k '$WORKDIR/alice' '$WORKDIR/payload.txt'" \
    "OK:" "sign stdout reports OK"

# ══════════════════════════════════════════════════════════════════════
# SECTION 3: VERIFICATION — HAPPY PATH
# ══════════════════════════════════════════════════════════════════════

header "Test: verify a valid signature"

"$SEAR" sign -k "$WORKDIR/alice" "$WORKDIR/payload.txt" 2>/dev/null
assert_ok "'$SEAR' verify -p '$WORKDIR/alice.pub' '$WORKDIR/payload.txt'" \
    "valid signature passes verification"

header "Test: verify stdout contains OK"

assert_stdout "'$SEAR' verify -p '$WORKDIR/alice.pub' '$WORKDIR/payload.txt'" \
    "OK:" "verify stdout reports OK"

header "Test: verify multiple files"

"$SEAR" sign -k "$WORKDIR/alice" "$WORKDIR/second.txt" 2>/dev/null
"$SEAR" sign -k "$WORKDIR/alice" "$WORKDIR/third.txt" 2>/dev/null
assert_ok "'$SEAR' verify -p '$WORKDIR/alice.pub' '$WORKDIR/second.txt' '$WORKDIR/third.txt'" \
    "multiple valid files all pass"

header "Test: verify with inline public key"

ALICE_PUB=$(cat "$WORKDIR/alice.pub")
"$SEAR" sign -k "$WORKDIR/alice" "$WORKDIR/payload.txt" 2>/dev/null
assert_ok "'$SEAR' verify -p \"$ALICE_PUB\" '$WORKDIR/payload.txt'" \
    "verify with inline public key string"

# ══════════════════════════════════════════════════════════════════════
# SECTION 4: VERIFICATION — ATTACK SCENARIOS
# ══════════════════════════════════════════════════════════════════════

header "Test: tampered file content"

"$SEAR" sign -k "$WORKDIR/alice" "$WORKDIR/payload.txt" 2>/dev/null
cp "$WORKDIR/payload.txt.sig" "$WORKDIR/payload.txt.sig.good"
echo "INJECTED MALICIOUS CODE" >> "$WORKDIR/payload.txt"

assert_fail "'$SEAR' verify -p '$WORKDIR/alice.pub' '$WORKDIR/payload.txt'" \
    "detects modified file content"

# Restore
cat > "$WORKDIR/payload.txt" <<'EOF'
#!/bin/sh
echo "legitimate deployment v2.1.0"
EOF
cp "$WORKDIR/payload.txt.sig.good" "$WORKDIR/payload.txt.sig"

header "Test: replaced file"

"$SEAR" sign -k "$WORKDIR/alice" "$WORKDIR/payload.txt" 2>/dev/null
echo "curl http://evil.example.com" > "$WORKDIR/payload.txt"
assert_fail "'$SEAR' verify -p '$WORKDIR/alice.pub' '$WORKDIR/payload.txt'" \
    "detects replaced file content"

cat > "$WORKDIR/payload.txt" <<'EOF'
#!/bin/sh
echo "legitimate deployment v2.1.0"
EOF

header "Test: attacker signs with untrusted key"

rm -f "$WORKDIR/payload.txt.sig"
ssh-keygen -Y sign -f "$WORKDIR/eve" -n file "$WORKDIR/payload.txt" 2>/dev/null
assert_fail "'$SEAR' verify -p '$WORKDIR/alice.pub' '$WORKDIR/payload.txt'" \
    "rejects signature from untrusted key"

header "Test: wrong key for verification"

"$SEAR" sign -k "$WORKDIR/alice" "$WORKDIR/payload.txt" 2>/dev/null
assert_fail "'$SEAR' verify -p '$WORKDIR/bob.pub' '$WORKDIR/payload.txt'" \
    "rejects wrong key"

header "Test: signature replay (file A sig on file B)"

"$SEAR" sign -k "$WORKDIR/alice" "$WORKDIR/payload.txt" 2>/dev/null
"$SEAR" sign -k "$WORKDIR/alice" "$WORKDIR/second.txt" 2>/dev/null
cp "$WORKDIR/payload.txt.sig" "$WORKDIR/second.txt.sig"
assert_fail "'$SEAR' verify -p '$WORKDIR/alice.pub' '$WORKDIR/second.txt'" \
    "rejects replayed signature from different file"

header "Test: namespace mismatch"

"$SEAR" sign -k "$WORKDIR/alice" -n "production" "$WORKDIR/payload.txt" 2>/dev/null
assert_fail "'$SEAR' verify -p '$WORKDIR/alice.pub' -n 'staging' '$WORKDIR/payload.txt'" \
    "rejects mismatched namespace"

header "Test: corrupted signature file"

"$SEAR" sign -k "$WORKDIR/alice" "$WORKDIR/payload.txt" 2>/dev/null
SIGSIZE=$(wc -c < "$WORKDIR/payload.txt.sig")
SIGMID=$((SIGSIZE / 2))
printf '\x00\x00\x00' | dd of="$WORKDIR/payload.txt.sig" bs=1 seek="$SIGMID" conv=notrunc 2>/dev/null
assert_fail "'$SEAR' verify -p '$WORKDIR/alice.pub' '$WORKDIR/payload.txt'" \
    "rejects corrupted signature"

header "Test: missing signature file"

rm -f "$WORKDIR/payload.txt.sig"
assert_fail "'$SEAR' verify -p '$WORKDIR/alice.pub' '$WORKDIR/payload.txt'" \
    "fails when .sig file missing"

header "Test: bit-flip in file"

"$SEAR" sign -k "$WORKDIR/alice" "$WORKDIR/payload.txt" 2>/dev/null
FILESIZE=$(wc -c < "$WORKDIR/payload.txt")
MIDPOINT=$((FILESIZE / 2))
printf '\xff' | dd of="$WORKDIR/payload.txt" bs=1 seek="$MIDPOINT" conv=notrunc 2>/dev/null
assert_fail "'$SEAR' verify -p '$WORKDIR/alice.pub' '$WORKDIR/payload.txt'" \
    "detects single bit-flip in file"

cat > "$WORKDIR/payload.txt" <<'EOF'
#!/bin/sh
echo "legitimate deployment v2.1.0"
EOF

header "Test: truncated file"

"$SEAR" sign -k "$WORKDIR/alice" "$WORKDIR/payload.txt" 2>/dev/null
dd if="$WORKDIR/payload.txt" of="$WORKDIR/payload.txt.trunc" bs=1 count=10 2>/dev/null
mv "$WORKDIR/payload.txt.trunc" "$WORKDIR/payload.txt"
assert_fail "'$SEAR' verify -p '$WORKDIR/alice.pub' '$WORKDIR/payload.txt'" \
    "detects truncated file"

cat > "$WORKDIR/payload.txt" <<'EOF'
#!/bin/sh
echo "legitimate deployment v2.1.0"
EOF

# ══════════════════════════════════════════════════════════════════════
# SECTION 5: PUBKEY VALIDATION
# ══════════════════════════════════════════════════════════════════════

header "Test: multi-key pubkey file"

"$SEAR" sign -k "$WORKDIR/alice" "$WORKDIR/payload.txt" 2>/dev/null
cat "$WORKDIR/alice.pub" "$WORKDIR/bob.pub" > "$WORKDIR/multi.pub"
assert_ok "'$SEAR' verify -p '$WORKDIR/multi.pub' '$WORKDIR/payload.txt'" \
    "multi-key file accepts signature from included key"

header "Test: multi-key file with comments and blank lines"

printf '# trusted keys\n%s\n\n%s\n' "$(cat "$WORKDIR/alice.pub")" "$(cat "$WORKDIR/bob.pub")" > "$WORKDIR/multi_comments.pub"
assert_ok "'$SEAR' verify -p '$WORKDIR/multi_comments.pub' '$WORKDIR/payload.txt'" \
    "multi-key file with comments and blank lines works"

header "Test: multi-key file rejects if signer not included"

"$SEAR" sign -k "$WORKDIR/eve" "$WORKDIR/payload.txt" 2>/dev/null
cat "$WORKDIR/alice.pub" "$WORKDIR/bob.pub" > "$WORKDIR/multi_noeve.pub"
assert_fail "'$SEAR' verify -p '$WORKDIR/multi_noeve.pub' '$WORKDIR/payload.txt'" \
    "multi-key file rejects signature from non-included key"

header "Test: multi-key file with invalid line"

printf '%s\nnot-a-key garbage\n' "$(cat "$WORKDIR/alice.pub")" > "$WORKDIR/multi_bad.pub"
assert_fail "'$SEAR' verify -p '$WORKDIR/multi_bad.pub' '$WORKDIR/payload.txt'" \
    "multi-key file with invalid line rejected"

header "Test: oversized pubkey file"

dd if=/dev/urandom bs=1024 count=10 2>/dev/null | base64 > "$WORKDIR/huge.pub"
assert_fail "'$SEAR' verify -p '$WORKDIR/huge.pub' '$WORKDIR/payload.txt'" \
    "rejects oversized pubkey file"

header "Test: non-SSH pubkey file"

echo "not-an-ssh-key just-garbage" > "$WORKDIR/fake.pub"
assert_fail "'$SEAR' verify -p '$WORKDIR/fake.pub' '$WORKDIR/payload.txt'" \
    "rejects non-SSH pubkey"

header "Test: empty pubkey file"

: > "$WORKDIR/empty.pub"
assert_fail "'$SEAR' verify -p '$WORKDIR/empty.pub' '$WORKDIR/payload.txt'" \
    "rejects empty pubkey file"

# ══════════════════════════════════════════════════════════════════════
# SECTION 6: EDGE CASES (SIGN/VERIFY)
# ══════════════════════════════════════════════════════════════════════

header "Test: binary file round-trip"

dd if=/dev/urandom of="$WORKDIR/binary.bin" bs=1024 count=4 2>/dev/null
"$SEAR" sign -k "$WORKDIR/alice" "$WORKDIR/binary.bin" 2>/dev/null
assert_ok "'$SEAR' verify -p '$WORKDIR/alice.pub' '$WORKDIR/binary.bin'" \
    "binary file sign+verify round-trip"

header "Test: file with spaces in name"

echo "spaced content" > "$WORKDIR/my file.txt"
"$SEAR" sign -k "$WORKDIR/alice" "$WORKDIR/my file.txt" 2>/dev/null
assert_ok "'$SEAR' verify -p '$WORKDIR/alice.pub' \"$WORKDIR/my file.txt\"" \
    "file with spaces in name"

header "Test: large file (1MB)"

dd if=/dev/urandom of="$WORKDIR/large.bin" bs=1024 count=1024 2>/dev/null
"$SEAR" sign -k "$WORKDIR/alice" "$WORKDIR/large.bin" 2>/dev/null
assert_ok "'$SEAR' verify -p '$WORKDIR/alice.pub' '$WORKDIR/large.bin'" \
    "1MB file sign+verify round-trip"

header "Test: empty file"

: > "$WORKDIR/empty.txt"
"$SEAR" sign -k "$WORKDIR/alice" "$WORKDIR/empty.txt" 2>/dev/null
assert_ok "'$SEAR' verify -p '$WORKDIR/alice.pub' '$WORKDIR/empty.txt'" \
    "empty file sign+verify round-trip"

header "Test: -- separator"

echo "dash content" > "$WORKDIR/-dashfile.txt"
"$SEAR" sign -k "$WORKDIR/alice" -- "$WORKDIR/-dashfile.txt" 2>/dev/null
assert_ok "'$SEAR' verify -p '$WORKDIR/alice.pub' -- '$WORKDIR/-dashfile.txt'" \
    "-- separator handles dash-prefixed filename"

header "Test: cross-key sign then verify"

"$SEAR" sign -k "$WORKDIR/bob" "$WORKDIR/payload.txt" 2>/dev/null
assert_ok "'$SEAR' verify -p '$WORKDIR/bob.pub' '$WORKDIR/payload.txt'" \
    "bob sign + bob verify works"
assert_fail "'$SEAR' verify -p '$WORKDIR/alice.pub' '$WORKDIR/payload.txt'" \
    "alice cannot verify bob's signature"

header "Test: ssh-keygen cross-compatibility"

# Sign with sear, verify with ssh-keygen
"$SEAR" sign -k "$WORKDIR/alice" "$WORKDIR/payload.txt" 2>/dev/null
echo "sear $(cat "$WORKDIR/alice.pub")" > "$WORKDIR/xcompat_signers"
assert_ok "ssh-keygen -Y verify -f '$WORKDIR/xcompat_signers' -I sear -n file -s '$WORKDIR/payload.txt.sig' < '$WORKDIR/payload.txt'" \
    "sear signature verifiable by ssh-keygen"

# Sign with ssh-keygen, verify with sear
rm -f "$WORKDIR/payload.txt.sig"
ssh-keygen -Y sign -f "$WORKDIR/alice" -n file "$WORKDIR/payload.txt" 2>/dev/null
assert_ok "'$SEAR' verify -p '$WORKDIR/alice.pub' '$WORKDIR/payload.txt'" \
    "ssh-keygen signature verifiable by sear"

# ══════════════════════════════════════════════════════════════════════
# SECTION 7: ENCRYPTION
# ══════════════════════════════════════════════════════════════════════

header "Test: encrypt a file"

echo "secret data" > "$WORKDIR/secret.txt"
"$SEAR" encrypt -r "$AGE_ALICE_RCPT" "$WORKDIR/secret.txt" 2>/dev/null
assert_ok "[ -f '$WORKDIR/secret.txt.age' ]" "encrypted file created"

header "Test: encrypt stdout contains OK"

echo "test" > "$WORKDIR/enc_stdout.txt"
assert_stdout "'$SEAR' encrypt -r '$AGE_ALICE_RCPT' '$WORKDIR/enc_stdout.txt'" \
    "OK:" "encrypt stdout reports OK"

header "Test: encrypt multiple files"

echo "secret1" > "$WORKDIR/s1.txt"
echo "secret2" > "$WORKDIR/s2.txt"
"$SEAR" encrypt -r "$AGE_ALICE_RCPT" "$WORKDIR/s1.txt" "$WORKDIR/s2.txt" 2>/dev/null
assert_ok "[ -f '$WORKDIR/s1.txt.age' ] && [ -f '$WORKDIR/s2.txt.age' ]" \
    "both encrypted files created"

header "Test: encrypt with -o custom output"

echo "custom out" > "$WORKDIR/crypt_custom.txt"
"$SEAR" encrypt -r "$AGE_ALICE_RCPT" -o "$WORKDIR/custom.age" "$WORKDIR/crypt_custom.txt" 2>/dev/null
assert_ok "[ -f '$WORKDIR/custom.age' ]" "custom output encrypted file created"

header "Test: encrypt -o with multiple files fails"

assert_fail "'$SEAR' encrypt -r '$AGE_ALICE_RCPT' -o out.age '$WORKDIR/s1.txt' '$WORKDIR/s2.txt'" \
    "-o with multiple files rejected"

header "Test: encrypt with ASCII armor"

echo "armor me" > "$WORKDIR/armor.txt"
"$SEAR" encrypt -r "$AGE_ALICE_RCPT" -a "$WORKDIR/armor.txt" 2>/dev/null
assert_ok "grep -q 'BEGIN AGE ENCRYPTED FILE' '$WORKDIR/armor.txt.age'" \
    "ASCII armor output"

header "Test: encrypt with multiple recipients"

echo "multi rcpt" > "$WORKDIR/multi.txt"
"$SEAR" encrypt -r "$AGE_ALICE_RCPT" -r "$AGE_BOB_RCPT" "$WORKDIR/multi.txt" 2>/dev/null
assert_ok "[ -f '$WORKDIR/multi.txt.age' ]" "encrypted with multiple recipients"

header "Test: encrypt with recipients file"

printf '%s\n%s\n' "$AGE_ALICE_RCPT" "$AGE_BOB_RCPT" > "$WORKDIR/recipients.txt"
echo "from file" > "$WORKDIR/rcptfile.txt"
"$SEAR" encrypt -R "$WORKDIR/recipients.txt" "$WORKDIR/rcptfile.txt" 2>/dev/null
assert_ok "[ -f '$WORKDIR/rcptfile.txt.age' ]" "encrypted with recipients file"

header "Test: encrypt no recipients fails"

assert_fail "'$SEAR' encrypt '$WORKDIR/secret.txt'" \
    "encrypt fails without recipients"

header "Test: encrypt no files fails"

assert_fail "'$SEAR' encrypt -r '$AGE_ALICE_RCPT'" \
    "encrypt fails without files"

header "Test: encrypt nonexistent file"

assert_fail "'$SEAR' encrypt -r '$AGE_ALICE_RCPT' '$WORKDIR/nope.txt'" \
    "encrypt fails on missing file"

# ══════════════════════════════════════════════════════════════════════
# SECTION 8: DECRYPTION
# ══════════════════════════════════════════════════════════════════════

header "Test: decrypt a file"

echo "decrypt me" > "$WORKDIR/dec_test.txt"
"$SEAR" encrypt -r "$AGE_ALICE_RCPT" "$WORKDIR/dec_test.txt" 2>/dev/null
rm "$WORKDIR/dec_test.txt"
"$SEAR" decrypt -i "$WORKDIR/age_alice.txt" "$WORKDIR/dec_test.txt.age" 2>/dev/null
assert_ok "[ -f '$WORKDIR/dec_test.txt' ]" "decrypted file created (strip .age)"
assert_ok "grep -q 'decrypt me' '$WORKDIR/dec_test.txt'" "decrypted content matches"

header "Test: decrypt stdout contains OK"

echo "test" > "$WORKDIR/dec_stdout.txt"
"$SEAR" encrypt -r "$AGE_ALICE_RCPT" "$WORKDIR/dec_stdout.txt" 2>/dev/null
rm "$WORKDIR/dec_stdout.txt"
assert_stdout "'$SEAR' decrypt -i '$WORKDIR/age_alice.txt' '$WORKDIR/dec_stdout.txt.age'" \
    "OK:" "decrypt stdout reports OK"

header "Test: decrypt with -o custom output"

echo "custom dec" > "$WORKDIR/dec_custom.txt"
"$SEAR" encrypt -r "$AGE_ALICE_RCPT" "$WORKDIR/dec_custom.txt" 2>/dev/null
"$SEAR" decrypt -i "$WORKDIR/age_alice.txt" -o "$WORKDIR/decrypted_custom.txt" "$WORKDIR/dec_custom.txt.age" 2>/dev/null
assert_ok "grep -q 'custom dec' '$WORKDIR/decrypted_custom.txt'" \
    "decrypt with custom output path"

header "Test: decrypt file without .age extension"

echo "no ext" > "$WORKDIR/noext.txt"
"$SEAR" encrypt -r "$AGE_ALICE_RCPT" -o "$WORKDIR/noext.encrypted" "$WORKDIR/noext.txt" 2>/dev/null
"$SEAR" decrypt -i "$WORKDIR/age_alice.txt" "$WORKDIR/noext.encrypted" 2>/dev/null
assert_ok "[ -f '$WORKDIR/noext.encrypted.dec' ]" "non-.age file gets .dec extension"

header "Test: decrypt with wrong identity fails"

echo "wrong key" > "$WORKDIR/wrongkey.txt"
"$SEAR" encrypt -r "$AGE_ALICE_RCPT" "$WORKDIR/wrongkey.txt" 2>/dev/null
assert_fail "'$SEAR' decrypt -i '$WORKDIR/age_bob.txt' '$WORKDIR/wrongkey.txt.age'" \
    "decrypt with wrong identity fails"

header "Test: decrypt no identity fails"

assert_fail "'$SEAR' decrypt '$WORKDIR/wrongkey.txt.age'" \
    "decrypt fails without identity"

header "Test: decrypt no files fails"

assert_fail "'$SEAR' decrypt -i '$WORKDIR/age_alice.txt'" \
    "decrypt fails without files"

header "Test: decrypt nonexistent file"

assert_fail "'$SEAR' decrypt -i '$WORKDIR/age_alice.txt' '$WORKDIR/nope.age'" \
    "decrypt fails on missing file"

header "Test: decrypt corrupted file"

echo "corrupt" > "$WORKDIR/corrupt.txt"
"$SEAR" encrypt -r "$AGE_ALICE_RCPT" "$WORKDIR/corrupt.txt" 2>/dev/null
printf '\x00\x00\x00' | dd of="$WORKDIR/corrupt.txt.age" bs=1 seek=10 conv=notrunc 2>/dev/null
assert_fail "'$SEAR' decrypt -i '$WORKDIR/age_alice.txt' '$WORKDIR/corrupt.txt.age'" \
    "decrypt rejects corrupted file"

# ══════════════════════════════════════════════════════════════════════
# SECTION 9: ENCRYPT + SIGN + VERIFY + DECRYPT (FULL PIPELINE)
# ══════════════════════════════════════════════════════════════════════

header "Test: full CI/CD pipeline"

cat > "$WORKDIR/deploy.sh" <<'DEPLOY'
#!/bin/sh
echo "production deploy — v3.0.0"
apt-get update && apt-get upgrade -y
systemctl restart nginx
DEPLOY

# Encrypt
"$SEAR" encrypt -r "$AGE_ALICE_RCPT" "$WORKDIR/deploy.sh" 2>/dev/null
assert_ok "[ -f '$WORKDIR/deploy.sh.age' ]" "pipeline: encrypt OK"

# Sign the encrypted file
"$SEAR" sign -k "$WORKDIR/alice" "$WORKDIR/deploy.sh.age" 2>/dev/null
assert_ok "[ -f '$WORKDIR/deploy.sh.age.sig' ]" "pipeline: sign OK"

# Verify the encrypted file
assert_ok "'$SEAR' verify -p '$WORKDIR/alice.pub' '$WORKDIR/deploy.sh.age'" \
    "pipeline: verify OK"

# Decrypt
rm -f "$WORKDIR/deploy.sh"
"$SEAR" decrypt -i "$WORKDIR/age_alice.txt" "$WORKDIR/deploy.sh.age" 2>/dev/null
assert_ok "grep -q 'production deploy' '$WORKDIR/deploy.sh'" \
    "pipeline: decrypt OK, content matches"

# Tamper with encrypted file after signing
printf '\xff' | dd of="$WORKDIR/deploy.sh.age" bs=1 seek=50 conv=notrunc 2>/dev/null
assert_fail "'$SEAR' verify -p '$WORKDIR/alice.pub' '$WORKDIR/deploy.sh.age'" \
    "pipeline: tampered encrypted file detected"

# ══════════════════════════════════════════════════════════════════════
# SECTION 10: ENCRYPT/DECRYPT ROUND-TRIP EDGE CASES
# ══════════════════════════════════════════════════════════════════════

header "Test: binary file encrypt/decrypt"

dd if=/dev/urandom of="$WORKDIR/binary_enc.bin" bs=1024 count=4 2>/dev/null
cp "$WORKDIR/binary_enc.bin" "$WORKDIR/binary_enc.bin.orig"
"$SEAR" encrypt -r "$AGE_ALICE_RCPT" "$WORKDIR/binary_enc.bin" 2>/dev/null
rm "$WORKDIR/binary_enc.bin"
"$SEAR" decrypt -i "$WORKDIR/age_alice.txt" "$WORKDIR/binary_enc.bin.age" 2>/dev/null
assert_ok "cmp -s '$WORKDIR/binary_enc.bin' '$WORKDIR/binary_enc.bin.orig'" \
    "binary encrypt/decrypt round-trip preserves content"

header "Test: large file encrypt/decrypt (1MB)"

dd if=/dev/urandom of="$WORKDIR/large_enc.bin" bs=1024 count=1024 2>/dev/null
cp "$WORKDIR/large_enc.bin" "$WORKDIR/large_enc.bin.orig"
"$SEAR" encrypt -r "$AGE_ALICE_RCPT" "$WORKDIR/large_enc.bin" 2>/dev/null
rm "$WORKDIR/large_enc.bin"
"$SEAR" decrypt -i "$WORKDIR/age_alice.txt" "$WORKDIR/large_enc.bin.age" 2>/dev/null
assert_ok "cmp -s '$WORKDIR/large_enc.bin' '$WORKDIR/large_enc.bin.orig'" \
    "1MB encrypt/decrypt round-trip preserves content"

header "Test: multi-recipient decrypt"

echo "multi key" > "$WORKDIR/multi_dec.txt"
"$SEAR" encrypt -r "$AGE_ALICE_RCPT" -r "$AGE_BOB_RCPT" "$WORKDIR/multi_dec.txt" 2>/dev/null

rm "$WORKDIR/multi_dec.txt"
"$SEAR" decrypt -i "$WORKDIR/age_alice.txt" "$WORKDIR/multi_dec.txt.age" 2>/dev/null
assert_ok "grep -q 'multi key' '$WORKDIR/multi_dec.txt'" \
    "alice can decrypt multi-recipient file"

rm "$WORKDIR/multi_dec.txt"
"$SEAR" decrypt -i "$WORKDIR/age_bob.txt" "$WORKDIR/multi_dec.txt.age" 2>/dev/null
assert_ok "grep -q 'multi key' '$WORKDIR/multi_dec.txt'" \
    "bob can decrypt multi-recipient file"

header "Test: -- separator in encrypt/decrypt"

echo "dash enc" > "$WORKDIR/-dashenc.txt"
"$SEAR" encrypt -r "$AGE_ALICE_RCPT" -- "$WORKDIR/-dashenc.txt" 2>/dev/null
assert_ok "[ -f '$WORKDIR/-dashenc.txt.age' ]" "encrypt with -- separator"
rm "$WORKDIR/-dashenc.txt"
"$SEAR" decrypt -i "$WORKDIR/age_alice.txt" -- "$WORKDIR/-dashenc.txt.age" 2>/dev/null
assert_ok "grep -q 'dash enc' '$WORKDIR/-dashenc.txt'" "decrypt with -- separator"

# ══════════════════════════════════════════════════════════════════════
# SECTION 11: SYMLINK PROTECTION
# ══════════════════════════════════════════════════════════════════════

header "Test: symlink .sig not deleted"

echo "important" > "$WORKDIR/important_file"
echo "to sign" > "$WORKDIR/symtest.txt"
ln -sf "$WORKDIR/important_file" "$WORKDIR/symtest.txt.sig"
"$SEAR" sign -k "$WORKDIR/alice" "$WORKDIR/symtest.txt" 2>/dev/null || true
# The symlink should still exist (not deleted)
assert_ok "[ -L '$WORKDIR/symtest.txt.sig' ] || [ -f '$WORKDIR/symtest.txt.sig' ]" \
    "symlink .sig preserved or replaced safely"
assert_ok "[ -f '$WORKDIR/important_file' ]" "symlink target not deleted"

# ══════════════════════════════════════════════════════════════════════
# SUMMARY
# ══════════════════════════════════════════════════════════════════════

header "Results"
printf 'Total:  %d\n' "$TOTAL"
printf 'Passed: %d\n' "$PASS"
printf 'Failed: %d\n' "$FAIL"

if [ "$FAIL" -eq 0 ]; then
    green "All tests passed."
    exit 0
else
    red "Some tests failed."
    exit 1
fi
