use rand::RngCore;

pub mod hash;
pub mod wrap;

/// Generate a cryptographically secure random key of the given length.
///
/// Uses the operating system's CSPRNG (`OsRng`).
pub fn generate_key(length: usize) -> Vec<u8> {
    let mut key = vec![0u8; length];
    rand::rngs::OsRng.fill_bytes(&mut key);
    key
}

fn xor(data: &[u8], key: &[u8]) -> Vec<u8> {
    assert_eq!(
        data.len(),
        key.len(),
        "data and key must have the same length"
    );
    data.iter().zip(key.iter()).map(|(d, k)| d ^ k).collect()
}

/// Encrypt plaintext by XORing it with the key.
///
/// # Panics
///
/// Panics if `key.len() != plaintext.len()`.
pub fn encrypt(plaintext: &[u8], key: &[u8]) -> Vec<u8> {
    xor(plaintext, key)
}

/// Decrypt ciphertext by XORing it with the key.
///
/// # Panics
///
/// Panics if `key.len() != ciphertext.len()`.
pub fn decrypt(ciphertext: &[u8], key: &[u8]) -> Vec<u8> {
    xor(ciphertext, key)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_key_length() {
        assert_eq!(generate_key(32).len(), 32);
    }

    #[test]
    fn generate_key_unique() {
        let a = generate_key(32);
        let b = generate_key(32);
        assert_ne!(a, b);
    }

    #[test]
    fn encrypt_decrypt_roundtrip() {
        let plaintext = b"hello world";
        let key = generate_key(plaintext.len());
        let ciphertext = encrypt(plaintext, &key);
        let decrypted = decrypt(&ciphertext, &key);
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    #[should_panic(expected = "data and key must have the same length")]
    fn encrypt_panics_on_short_key() {
        encrypt(b"hello", b"abc");
    }

    #[test]
    fn empty_input() {
        let key = generate_key(0);
        let ciphertext = encrypt(&[], &key);
        assert!(ciphertext.is_empty());
        let decrypted = decrypt(&ciphertext, &key);
        assert!(decrypted.is_empty());
    }

    #[test]
    fn different_keys_produce_different_ciphertext() {
        let plaintext = b"hello world";
        let key_a = generate_key(plaintext.len());
        let key_b = generate_key(plaintext.len());
        let ct_a = encrypt(plaintext, &key_a);
        let ct_b = encrypt(plaintext, &key_b);
        assert_ne!(ct_a, ct_b);
    }
}
