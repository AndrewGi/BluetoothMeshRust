use crate::crypto::aes::AESCipher;
use crate::crypto::key::{AppKey, EncryptionKey, Key, NetKey, PrivacyKey, KEY_LEN, ZERO_KEY};
use crate::crypto::{NetworkID, Salt, AID};
use crate::mesh::NID;
use aes_soft::Aes128;

/// k1 function from Mesh Core v1.0. N==`bytes` and P==`extra`.
#[must_use]
pub fn k1(bytes: &[u8], salt: Salt, extra: &'static str) -> Key {
    let t = AESCipher::from(salt).aes_cmac(bytes);
    AESCipher::from(t).aes_cmac(extra.as_bytes())
}
pub fn k2(key: Key, p: impl AsRef<[u8]>) -> (NID, EncryptionKey, PrivacyKey) {
    k2_bytes(key, p.as_ref())
}
#[must_use]
pub fn k2_bytes(n: Key, p: &[u8]) -> (NID, EncryptionKey, PrivacyKey) {
    assert!(!p.is_empty(), "p must have at least one byte");
    let salt = s1("smk2"); //From Mesh Core v1.0 Part 3.8.2.6
                           // Copied from Ero Bluetooth Mesh on github (I wrote it)
    let t = AESCipher::from(salt).aes_cmac(n.as_ref());
    let cipher = AESCipher::from(t);
    let t_1 = cipher.aes_cmac_slice(&[p, &[0x01]]);
    let t_2 = cipher.aes_cmac_slice(&[t_1.as_ref(), p, &[0x02]]);
    let t_3 = cipher.aes_cmac_slice(&[t_2.as_ref(), p, &[0x03]]);

    (
        NID::new(t_1.as_ref()[15] & 0x7F),
        EncryptionKey::new(t_2),
        PrivacyKey::new(t_3),
    )
}
#[must_use]
pub fn k3(key: NetKey) -> NetworkID {
    unimplemented!()
}
#[must_use]
pub fn k4(key: AppKey) -> AID {
    unimplemented!()
}
#[must_use]
pub fn s1(m: impl AsRef<[u8]>) -> Salt {
    s1_bytes(m.as_ref())
}
#[must_use]
pub fn s1_bytes(m: &[u8]) -> Salt {
    AESCipher::new(ZERO_KEY).aes_cmac(m).as_salt()
}

#[must_use]
pub fn id128(n: Key, s: &'static str) {
    unimplemented!()
}
