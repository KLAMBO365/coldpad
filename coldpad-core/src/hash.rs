use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

/// Compute the SHA-256 hash of `data` and return it as a lowercase hex string.
pub fn compute(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    format!("{:x}", hasher.finalize())
}

/// Verify that `data` hashes to `expected` using a constant-time comparison.
///
/// `expected` must be a 64-character lowercase hex string.
pub fn verify(data: &[u8], expected: &str) -> bool {
    let actual = compute(data);
    actual.as_bytes().ct_eq(expected.as_bytes()).into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compute_produces_hex() {
        let hash = compute(b"hello");
        assert_eq!(hash.len(), 64);
        assert!(hash.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn verify_correct_hash() {
        let hash = compute(b"hello");
        assert!(verify(b"hello", &hash));
    }

    #[test]
    fn verify_incorrect_hash() {
        let hash = compute(b"hello");
        assert!(!verify(b"world", &hash));
    }

    #[test]
    fn verify_empty_input() {
        let hash = compute(b"");
        assert!(verify(b"", &hash));
        assert!(!verify(b"x", &hash));
    }
}
