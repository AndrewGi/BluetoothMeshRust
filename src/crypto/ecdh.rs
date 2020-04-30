use crate::provisioning::protocol::PublicKey;
use std::convert::TryInto;

#[derive(Copy, Clone, PartialOrd, PartialEq, Ord, Eq, Debug, Hash)]
pub enum Error {
    KeyGenerationProblem,
    EarlyPublicKeyAgreementKey,
}

#[derive(Clone)]
pub struct DerivedPublicKey {
    key: ring::agreement::PublicKey,
}
impl DerivedPublicKey {}
impl AsRef<[u8]> for DerivedPublicKey {
    fn as_ref(&self) -> &[u8] {
        &self.key.as_ref()[1..]
    }
}
impl From<&DerivedPublicKey> for PublicKey {
    fn from(k: &DerivedPublicKey) -> Self {
        let b = k.as_ref();
        assert_eq!(64, b.len(), "derived public key wrong length");
        PublicKey {
            x: (&b[..32]).try_into().expect("length checked above"),
            y: (&b[32..64]).try_into().expect("length checked above"),
        }
    }
}
pub struct PrivateKey {
    key: ring::agreement::EphemeralPrivateKey,
}
impl PrivateKey {
    pub fn new() -> Result<PrivateKey, Error> {
        // ring is annoying and only allows `SystemRandom` which makes it hard to support
        // bare-metal environments so this will need to change in the future.
        Ok(PrivateKey {
            key: ring::agreement::EphemeralPrivateKey::generate(
                &ring::agreement::ECDH_P256,
                &ring::rand::SystemRandom::new(),
            )
            .map_err(|_| Error::KeyGenerationProblem)?,
        })
    }
    pub fn public_key(&self) -> Result<DerivedPublicKey, Error> {
        Ok(DerivedPublicKey {
            key: self
                .key
                .compute_public_key()
                .map_err(|_| Error::KeyGenerationProblem)?,
        })
    }
    pub fn agree<D, F: FnOnce(&[u8]) -> D>(
        self,
        public_key: &PublicKey,
        kdf: F,
    ) -> Result<D, Error> {
        const ELEM_LEN: usize = 32;
        let mut p_key = [0_u8; ELEM_LEN * 2 + 1];
        p_key[0] = 0x04;
        p_key[1..1 + ELEM_LEN].copy_from_slice(public_key.x.as_ref());
        p_key[1 + ELEM_LEN..].copy_from_slice(public_key.y.as_ref());
        ring::agreement::agree_ephemeral(
            self.key,
            &ring::agreement::UnparsedPublicKey::new(&ring::agreement::ECDH_P256, p_key.as_ref()),
            Error::EarlyPublicKeyAgreementKey,
            |b| Ok(kdf(b)),
        )
    }
}
