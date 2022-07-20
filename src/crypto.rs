use rand::{CryptoRng, RngCore};

pub(crate) fn dh_generate<T>(rng: T) -> (x25519_dalek::EphemeralSecret, x25519_dalek::PublicKey)
where
    T: RngCore + CryptoRng,
{
    let private = x25519_dalek::EphemeralSecret::new(rng);
    let public = x25519_dalek::PublicKey::from(&private);

    (private, public)
}

#[inline]
pub(crate) fn dh(
    private: x25519_dalek::EphemeralSecret,
    public: &x25519_dalek::PublicKey,
) -> x25519_dalek::SharedSecret {
    private.diffie_hellman(public)
}
