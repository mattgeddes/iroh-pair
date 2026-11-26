use crate::error::{PairError, Result};
use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305, Nonce,
};
use hkdf::Hkdf;
use rand_core::OsRng;
use sha2::Sha256;
use x25519_dalek::{PublicKey, StaticSecret};

pub const ALPN: &[u8] = b"iroh-pair/1";

pub fn generate_keypair() -> (StaticSecret, PublicKey) {
    let secret = StaticSecret::random_from_rng(OsRng);
    let public = PublicKey::from(&secret);
    (secret, public)
}

pub fn dh(local_sk: &StaticSecret, remote_pk: &PublicKey) -> Result<[u8; 32]> {
    let shared = local_sk.diffie_hellman(remote_pk);
    if !shared.was_contributory() {
        return Err(PairError::Crypto(
            "non-contributory (low-order) DH result".into(),
        ));
    }
    Ok(shared.to_bytes())
}

pub fn transcript(
    pk_a: &[u8; 32],
    pk_b: &[u8; 32],
    initiator_id: &[u8; 32],
    responder_id: &[u8; 32],
) -> [u8; 32] {
    let (first, second) = if pk_a <= pk_b {
        (pk_a, pk_b)
    } else {
        (pk_b, pk_a)
    };
    let mut hasher = blake3::Hasher::new();
    hasher.update(first);
    hasher.update(second);
    // Bind the transcript to both endpoints' long-term iroh identities so the
    // SAS reflects who is on the other end, not just the ephemeral keys.
    hasher.update(initiator_id);
    hasher.update(responder_id);
    hasher.update(ALPN);
    let out = hasher.finalize();
    let mut arr = [0u8; 32];
    arr.copy_from_slice(out.as_bytes());
    arr
}

pub fn sas_from_transcript(transcript: &[u8; 32]) -> u32 {
    // first 3 bytes -> 24-bit integer
    ((transcript[0] as u32) << 16) | ((transcript[1] as u32) << 8) | (transcript[2] as u32)
}

pub fn derive_session_key(dh_shared: &[u8; 32], transcript: &[u8; 32]) -> [u8; 32] {
    derive_session_key_with_info(dh_shared, transcript, b"iroh-pair session key")
}

pub fn derive_session_key_with_info(
    dh_shared: &[u8; 32],
    transcript: &[u8; 32],
    info: &[u8],
) -> [u8; 32] {
    let hk = Hkdf::<Sha256>::new(Some(transcript), dh_shared);
    let mut okm = [0u8; 32];
    hk.expand(info, &mut okm).expect("hkdf expand");
    okm
}

/// Derive two independent directional keys to avoid nonce reuse across
/// initiator->responder and responder->initiator transfers.
pub fn derive_directional_keys(
    dh_shared: &[u8; 32],
    transcript: &[u8; 32],
) -> ([u8; 32], [u8; 32]) {
    let i2r =
        derive_session_key_with_info(dh_shared, transcript, b"iroh-pair initiator->responder");
    let r2i =
        derive_session_key_with_info(dh_shared, transcript, b"iroh-pair responder->initiator");
    (i2r, r2i)
}

// Random 12-byte nonce is prepended to the ciphertext so callers never have to
// manage counters. Random nonces are safe only within the per-key message budget
// (birthday bound); for very high volumes use a counter-based or XChaCha nonce.
const NONCE_LEN: usize = 12;

pub fn encrypt(key: &[u8; 32], plaintext: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
    use chacha20poly1305::aead::Payload;
    use rand_core::RngCore;
    let cipher = ChaCha20Poly1305::new(key.into());
    let mut nonce_bytes = [0u8; NONCE_LEN];
    rand_core::OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);
    let ct = cipher
        .encrypt(
            nonce,
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|e| PairError::Crypto(e.to_string()))?;
    let mut out = Vec::with_capacity(NONCE_LEN + ct.len());
    out.extend_from_slice(&nonce_bytes);
    out.extend_from_slice(&ct);
    Ok(out)
}

pub fn decrypt(key: &[u8; 32], ciphertext: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
    if ciphertext.len() < NONCE_LEN {
        return Err(PairError::Crypto("ciphertext too short".into()));
    }
    let cipher = ChaCha20Poly1305::new(key.into());
    let nonce = Nonce::from_slice(&ciphertext[..NONCE_LEN]);
    cipher
        .decrypt(
            nonce,
            chacha20poly1305::aead::Payload {
                msg: &ciphertext[NONCE_LEN..],
                aad,
            },
        )
        .map_err(|e| PairError::Crypto(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn transcript_consistent() {
        let a = [1u8; 32];
        let b = [2u8; 32];
        let id = [0u8; 32];
        let t1 = transcript(&a, &b, &id, &id);
        let t2 = transcript(&b, &a, &id, &id);
        assert_eq!(t1, t2);
    }

    #[test]
    fn dh_consistency() {
        let (ska, pka) = generate_keypair();
        let (skb, pkb) = generate_keypair();
        let shared_a = dh(&ska, &pkb).unwrap();
        let shared_b = dh(&skb, &pka).unwrap();
        assert_eq!(shared_a, shared_b);
    }

    #[test]
    fn sas_matches() {
        let a = [1u8; 32];
        let b = [2u8; 32];
        let t = transcript(&a, &b, &[0u8; 32], &[0u8; 32]);
        let s1 = sas_from_transcript(&t);
        let s2 = sas_from_transcript(&t);
        assert_eq!(s1, s2);
    }

    #[test]
    fn encrypt_roundtrip() {
        let key = [7u8; 32];
        let ct = encrypt(&key, b"hello", b"").unwrap();
        let pt = decrypt(&key, &ct, b"").unwrap();
        assert_eq!(pt, b"hello");
    }
}
