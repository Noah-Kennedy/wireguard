use blake2::{Blake2s, Blake2s256, Digest};
use x25519_dalek::{PublicKey, ReusableSecret, SharedSecret};

pub(crate) fn dh_generate() -> ReusableSecret {
    x25519_dalek::ReusableSecret::new(rand_core::OsRng)
}

pub(crate) fn dh(private_key: &ReusableSecret, public_key: &PublicKey) -> [u8; 32] {
    private_key.diffie_hellman(public_key).to_bytes()
}

pub(crate) fn hmac(key: &[u8], input: &[&[u8]], output: &mut [u8]) {
    use blake2::digest::FixedOutput;
    use hmac::{Mac, SimpleHmac};

    let mut hmac: SimpleHmac<Blake2s256> = SimpleHmac::new_from_slice(key).unwrap();

    for slice in input {
        hmac.update(slice);
    }

    hmac.finalize_into(blake2::digest::generic_array::GenericArray::from_mut_slice(
        output,
    ));
}

pub(crate) fn hash(input: &[&[u8]], output: &mut [u8]) {
    let mut hasher: Blake2s256 = Blake2s::new();

    for slice in input {
        hasher.update(slice);
    }

    hasher.finalize_into(blake2::digest::generic_array::GenericArray::from_mut_slice(
        output,
    ));
}

pub(crate) fn unseal_aead(
    key: &[u8; 32],
    counter: u64,
    plaintext: &mut Vec<u8>,
    auth: &[u8],
) -> bool {
    use chacha20poly1305::{AeadInPlace, ChaCha20Poly1305, Key, KeyInit, Nonce};

    let key = Key::from_slice(key);

    let chacha = ChaCha20Poly1305::new(key);

    let mut nonce = [0u8; 12];
    nonce[4..].clone_from_slice(&counter.to_le_bytes());
    let nonce = Nonce::from_slice(&nonce);

    chacha.decrypt_in_place(nonce, auth, plaintext).is_ok()
}

pub(crate) fn seal_aead(key: &[u8; 32], counter: u64, plaintext: &mut Vec<u8>, auth: &[u8]) {
    use chacha20poly1305::{AeadInPlace, ChaCha20Poly1305, Key, KeyInit, Nonce};

    let key = Key::from_slice(key);

    let chacha = ChaCha20Poly1305::new(key);

    let mut nonce = [0u8; 12];
    nonce[4..].clone_from_slice(&counter.to_le_bytes());
    let nonce = Nonce::from_slice(&nonce);

    chacha.encrypt_in_place(nonce, auth, plaintext).unwrap();
}
