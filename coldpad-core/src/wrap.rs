use aes_gcm::{
    Aes256Gcm, Nonce,
    aead::{Aead, KeyInit},
};
use argon2::{Algorithm, Argon2, Params, Version};
use rand::RngCore;

const HEADER: &str = "coldpad-wrapped-key-v1";
const SALT_LEN: usize = 16;
const NONCE_LEN: usize = 12;
const KEY_LEN: usize = 32;

const ARGON2_M_KIB: u32 = 19456;
const ARGON2_T: u32 = 2;
const ARGON2_P: u32 = 1;

#[derive(Debug, PartialEq)]
pub enum WrapError {
    InvalidFormat,
    AuthenticationFailed,
}

impl std::fmt::Display for WrapError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            WrapError::InvalidFormat => write!(f, "invalid wrapped key format"),
            WrapError::AuthenticationFailed => {
                write!(f, "wrong password or tampered wrapped key")
            }
        }
    }
}

impl std::error::Error for WrapError {}

fn derive_key(password: &str, salt: &[u8]) -> Result<[u8; KEY_LEN], WrapError> {
    let params = Params::new(ARGON2_M_KIB, ARGON2_T, ARGON2_P, Some(KEY_LEN))
        .map_err(|_| WrapError::InvalidFormat)?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut key = [0u8; KEY_LEN];
    argon2
        .hash_password_into(password.as_bytes(), salt, &mut key)
        .map_err(|_| WrapError::InvalidFormat)?;
    Ok(key)
}

/// Wrap a raw key with a password using Argon2id + AES-256-GCM.
///
/// Returns ASCII text that can be stored in a `.otp.key` file.
pub fn wrap_key(key: &[u8], password: &str) -> Vec<u8> {
    let mut salt = [0u8; SALT_LEN];
    let mut nonce = [0u8; NONCE_LEN];
    rand::rngs::OsRng.fill_bytes(&mut salt);
    rand::rngs::OsRng.fill_bytes(&mut nonce);

    let derived = derive_key(password, &salt).expect("argon2 params are valid");
    let cipher = Aes256Gcm::new_from_slice(&derived).expect("key length is correct");
    let nonce_slice = Nonce::from_slice(&nonce);
    let ciphertext = cipher
        .encrypt(nonce_slice, key)
        .expect("encryption should succeed");

    let mut output = Vec::new();
    output.extend_from_slice(HEADER.as_bytes());
    output.push(b'\n');
    output.extend_from_slice(b"salt:");
    output.extend_from_slice(hex::encode(salt).as_bytes());
    output.push(b'\n');
    output.extend_from_slice(b"nonce:");
    output.extend_from_slice(hex::encode(nonce).as_bytes());
    output.push(b'\n');
    output.extend_from_slice(b"ciphertext:");
    output.extend_from_slice(hex::encode(&ciphertext).as_bytes());
    output.push(b'\n');
    output
}

/// Unwrap a password-protected key.
pub fn unwrap_key(wrapped: &[u8], password: &str) -> Result<Vec<u8>, WrapError> {
    let text = std::str::from_utf8(wrapped).map_err(|_| WrapError::InvalidFormat)?;
    let mut lines = text.lines();

    let header = lines.next().ok_or(WrapError::InvalidFormat)?;
    if header != HEADER {
        return Err(WrapError::InvalidFormat);
    }

    let salt_line = lines.next().ok_or(WrapError::InvalidFormat)?;
    let nonce_line = lines.next().ok_or(WrapError::InvalidFormat)?;
    let ciphertext_line = lines.next().ok_or(WrapError::InvalidFormat)?;

    let salt = parse_prefixed_hex(salt_line, "salt:")?;
    let nonce = parse_prefixed_hex(nonce_line, "nonce:")?;
    let ciphertext = parse_prefixed_hex(ciphertext_line, "ciphertext:")?;

    if salt.len() != SALT_LEN || nonce.len() != NONCE_LEN {
        return Err(WrapError::InvalidFormat);
    }

    let derived = derive_key(password, &salt)?;
    let cipher = Aes256Gcm::new_from_slice(&derived).map_err(|_| WrapError::InvalidFormat)?;
    let nonce_slice = Nonce::from_slice(&nonce);

    cipher
        .decrypt(nonce_slice, ciphertext.as_ref())
        .map_err(|_| WrapError::AuthenticationFailed)
}

fn parse_prefixed_hex(line: &str, prefix: &str) -> Result<Vec<u8>, WrapError> {
    let value = line.strip_prefix(prefix).ok_or(WrapError::InvalidFormat)?;
    hex::decode(value.trim()).map_err(|_| WrapError::InvalidFormat)
}

pub fn is_wrapped_key(data: &[u8]) -> bool {
    data.starts_with(HEADER.as_bytes()) && data.get(HEADER.len()).copied() == Some(b'\n')
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wrap_unwrap_roundtrip() {
        let key = b"hello world key";
        let wrapped = wrap_key(key, "password");
        let unwrapped = unwrap_key(&wrapped, "password").unwrap();
        assert_eq!(unwrapped, key);
    }

    #[test]
    fn wrong_password_fails() {
        let key = b"secret key";
        let wrapped = wrap_key(key, "right");
        let result = unwrap_key(&wrapped, "wrong");
        assert_eq!(result, Err(WrapError::AuthenticationFailed));
    }

    #[test]
    fn tampered_ciphertext_fails() {
        let key = b"secret key";
        let wrapped = wrap_key(key, "password");
        let text = String::from_utf8(wrapped).unwrap();
        let lines: Vec<&str> = text.lines().collect();
        let ct_line = lines.last().unwrap();
        let mut ct_bytes =
            hex::decode(ct_line.strip_prefix("ciphertext:").unwrap().trim()).unwrap();
        ct_bytes[0] ^= 0xff;
        let mut tampered = lines[..lines.len() - 1].join("\n");
        tampered.push('\n');
        tampered.push_str(&format!("ciphertext:{}\n", hex::encode(ct_bytes)));
        let result = unwrap_key(tampered.as_bytes(), "password");
        assert_eq!(result, Err(WrapError::AuthenticationFailed));
    }

    #[test]
    fn tampered_header_fails() {
        let key = b"secret key";
        let wrapped = wrap_key(key, "password");
        let mut text = String::from_utf8(wrapped).unwrap();
        text = text.replace("v1", "v2");
        let result = unwrap_key(text.as_bytes(), "password");
        assert_eq!(result, Err(WrapError::InvalidFormat));
    }

    #[test]
    fn detects_wrapped_key() {
        let wrapped = wrap_key(b"key", "pw");
        assert!(is_wrapped_key(&wrapped));
        assert!(!is_wrapped_key(b"plain key bytes"));
    }
}
