# sear

Sign, verify, encrypt and decrypt files with SSH keys and age.

`sear` wraps `ssh-keygen` and `age` into a single tool for YubiKey-based
file signing and encryption. SSH signing uses FIDO2 ed25519-sk keys
(touch to sign), age encryption uses PIV via
[age-plugin-yubikey](https://github.com/str4d/age-plugin-yubikey)
(PIN + touch).

## Install

```
curl -fsSL https://raw.githubusercontent.com/8ff/sear/main/install.sh | sudo sh
```

Or download a binary from [Releases](../../releases), or build from source:

```
go build -o sear .
```

### Dependencies

| | Required | Optional |
|---|---|---|
| Signing | `ssh-keygen` | |
| Encryption | `age` | `age-plugin-yubikey` (YubiKey PIV) |
| Key management | | `ykman` (YubiKey admin) |

```
# macOS
brew install age age-plugin-yubikey ykman libfido2

# FreeBSD
pkg install age age-plugin-yubikey yubikey-manager libfido2

# Linux
apt install age yubikey-manager libfido2-tools
```

## Usage

```
sear <command> [flags] FILE...

Signing & Verification:
  sign         Sign files with SSH key (via ssh-agent)
  verify       Verify file signatures
  seal         Encrypt + sign in one step
  unseal       Verify + decrypt in one step

Encryption:
  encrypt      Encrypt files with age
  decrypt      Decrypt files with age

Key Management:
  keygen       Generate ed25519-sk signing key on YubiKey
  age-keygen   Generate age encryption key on YubiKey
```

Run `sear <command> -h` for per-command help.

### Quick start

```bash
# 1. Create SSH signing key on YubiKey
sear keygen -C mykey

# 2. Sign a file (touch YubiKey)
sear sign document.pdf

# 3. Verify
sear verify document.pdf

# 4. Create age encryption key on YubiKey (one-time)
sear age-keygen -o age-identity.txt

# 5. Encrypt for a recipient
sear encrypt -r age1yubikey1q... secrets.env

# 6. Decrypt (PIN + touch)
sear decrypt -i age-identity.txt secrets.env.age
```

### Seal / Unseal (encrypt + sign in one step)

For CI/CD delivery — encrypt and sign on your machine, verify and decrypt
on the server:

```bash
# Sender
sear seal -r age1... secrets.env
# produces secrets.env.age + secrets.env.age.sig

# Receiver
sear unseal -p deploy.pub -i ci-identity.txt secrets.env.age
# verifies signature, then decrypts
```

### Key naming

The `-C` flag to `sear keygen` sets both the SSH key comment and the
FIDO2 application ID (`ssh:NAME`) on the YubiKey. This lets you match
key files on disk to credentials on the hardware:

```bash
sear keygen -C prod-deploy -f ~/.ssh/deploy_sk
# Comment: prod-deploy
# App ID:  ssh:prod-deploy
# Visible: ykman fido credentials list
```

## How it works

- **Signing** uses `ssh-keygen -Y sign/verify` (the SSHSIG protocol).
  Signatures are compatible with `ssh-keygen` — you can sign with `sear`
  and verify with `ssh-keygen`, or vice versa.

- **Encryption** uses `age` with optional YubiKey PIV support via
  `age-plugin-yubikey`.

- **No private keys on disk** for signing. FIDO2 keys live on the
  YubiKey; `ssh-keygen` talks to the hardware directly.

## Test

```
go build -o sear . && ./test-sear.sh
```

Runs 106 tests covering signing, verification, encryption, decryption,
attack scenarios (tampered files, wrong keys, replayed signatures,
namespace mismatches, corrupted data), edge cases (binary files, empty
files, spaces in names, 1MB files), and cross-compatibility with
`ssh-keygen`.

## License

GPL-3.0
