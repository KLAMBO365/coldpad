<p align="center">
  <img src="https://img.shields.io/badge/version-0.2.0-blue.svg" alt="version">
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

### Guided mode

Run a guided workflow for encryption, decryption, key generation, or file info:

```console
$ coldpad secure
```

The guided mode previews planned writes and asks for confirmation before creating
or overwriting files.

### Encrypt

Encrypt text, pipe input, or a file:

```console
$ coldpad encrypt "hello world"
  Wrote output.otp
    Wrote output.otp.key

$ coldpad encrypt -o secret "hello world"

$ coldpad encrypt --base64 "hello world"

$ echo "text" | coldpad encrypt

$ coldpad encrypt --file document.pdf
```

Text input and `--file` cannot be used together. Use one input source per command.

The `--hash` flag writes a SHA-256 file for integrity verification:

```console
$ coldpad encrypt --hash "important data"
```

### Decrypt

```console
$ coldpad decrypt output.otp
hello world

$ coldpad decrypt output.otp -o plain.txt

$ coldpad decrypt --file output.otp

$ coldpad decrypt output.otp --base64
```

When a hash file is present, decryption verifies it before writing `-o` output.

### Key generation

```console
$ coldpad keygen -l 32
  Wrote key_1734567890.key

$ coldpad keygen -l 32 -o mykey.key --hex
```

### Info

Show details about an encrypted file:

```console
$ coldpad info output.otp

$ coldpad info --file output.otp
```

## Commands

| command    | alias | description                     |
|------------|-------|---------------------------------|
| `encrypt`  | `e`   | encrypt text, pipe, or file     |
| `decrypt`  | `d`   | decrypt a `.otp` ciphertext     |
| `keygen`   | `k`   | generate a random key of N bytes|
| `info`     | `i`   | show info about a `.otp` file   |
| `secure`   |       | start a guided secure workflow  |

## Flags

| flag            | command                  | description                         |
|-----------------|--------------------------|-------------------------------------|
| `-o, --output`  | encrypt, decrypt         | custom output path or stem          |
| `-f, --force`   | encrypt, keygen          | overwrite existing output files     |
| `--hash`        | encrypt                  | write SHA-256 hash for integrity    |
| `--base64`      | encrypt, decrypt, keygen | encode/decode as base64             |
| `--hex`         | encrypt, decrypt, keygen | encode/decode as hex                |
| `--file`        | encrypt, decrypt, info   | read input from a file flag         |
| `-l, --length`  | keygen                   | key length in bytes                 |

## License

MIT. See [LICENSE](LICENSE).
