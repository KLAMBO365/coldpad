<p align="center">
  <img src="https://img.shields.io/badge/version-0.3.0-blue.svg" alt="version">
  <img src="https://img.shields.io/badge/license-MIT-green.svg" alt="license">
</p>

<h1 align="center">coldpad</h1>

<p align="center">
  <em>Encrypt and decrypt data with one-time pads.</em><br>
  XOR-based, OsRng-seeded keys, optional SHA-256 integrity verification.
</p>

---

## About

Coldpad encrypts data with one-time pads. It generates random keys with OsRng and XORs them with your input.

## Security Considerations

**One-time pads are only secure when used correctly:**

- The key must be **at least as long** as the message.
- The key must be **truly random** (coldpad uses `OsRng`).
- The key must **never be reused** for a different message.
- The key must be kept **secret** and stored separately from the ciphertext.

If you reuse a key, an attacker can XOR two ciphertexts together to recover information about the plaintexts. Coldpad generates a fresh key for every encryption, but you are responsible for keeping it safe.

The optional SHA-256 file is an integrity check for this workflow. It is not authenticated encryption.

## Installation

### From source

```console
$ git clone https://github.com/KLAMBO365/coldpad.git
$ cd coldpad
$ cargo build --release
$ ./target/release/coldpad --help
```

## Usage

### Recommended: guided mode

Run a guided workflow for encryption, decryption, key generation, or file info:

```console
$ coldpad secure
```

The guided mode previews planned writes and asks for confirmation before creating
or overwriting files.

### Scriptable recipes

Use direct commands when you want repeatable shell history, scripts, or CI jobs.

Encrypt text:

```console
$ coldpad encrypt "hello world"
  Wrote output.otp
    Wrote output.otp.key
```

Encrypt with a custom output stem:

```console
$ coldpad encrypt -o secret "hello world"
```

Encrypt a file:

```console
$ coldpad encrypt --file document.pdf
```

Encrypt piped input:

```console
$ echo "text" | coldpad encrypt
```

Write a SHA-256 integrity file:

```console
$ coldpad encrypt --hash "important data"
```

Password-protect the generated key:

```console
$ coldpad encrypt --wrap-key --hash "important data"
```

Use text encoding for files that need it:

```console
$ coldpad encrypt --encoding base64 "hello world"
$ coldpad decrypt output.otp --encoding base64
```

Decrypt:

```console
$ coldpad decrypt output.otp
hello world

$ coldpad decrypt output.otp -o plain.txt
```

Generate and manage keys:

```console
$ coldpad key generate --length 32
  Wrote key_1734567890.key

$ coldpad key generate --length 32 --output mykey.key --encoding hex

$ coldpad key wrap mykey.key --output wrapped.key

$ coldpad key unwrap wrapped.key --output mykey.key
```

Show details about an encrypted file:

```console
$ coldpad info output.otp
```

### Command notes

Text input and `--file` cannot be used together. Use one input source per command.

The `--wrap-key` flag password-protects the generated `.otp.key` file instead
of writing the raw one-time pad key to disk.

When a hash file is present, decryption verifies it before writing `-o` output.
For wrapped keys, coldpad prompts for the password in a terminal; use
`--password-file` for non-interactive runs.

Use `--encoding raw`, `--encoding base64`, or `--encoding hex` when ciphertext
and raw key files need a specific representation. Wrapped key files are already
password-protected and do not use the raw key encoding.

## Commands

| command    | alias | description                         |
|------------|-------|-------------------------------------|
| `secure`   |       | start a guided secure workflow      |
| `encrypt`  | `e`   | encrypt text, pipe, or file         |
| `decrypt`  | `d`   | decrypt a `.otp` ciphertext         |
| `info`     | `i`   | show info about a `.otp` file       |
| `key`      |       | generate, wrap, or unwrap key files |

Run `coldpad <command> --help` for command-specific options.

## License

MIT. See [LICENSE](LICENSE).
