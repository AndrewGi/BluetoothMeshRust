use crate::crypto::key::{AppKey, EncryptionKey, Key, NetKey, PrivacyKey};
use crate::crypto::{NetworkID, Salt, AID};
use crate::mesh::NID;

#[must_use]
pub fn k1(bytes: &[u8], salt: Salt, extra: &'static str) -> Key {
    unimplemented!()
}
#[must_use]
pub fn id128(n: Key, s: &'static str) {
    unimplemented!()
}
#[must_use]
pub fn k3(key: NetKey) -> NetworkID {
    unimplemented!()
}
#[must_use]
pub fn k2(key: Key) -> (NID, EncryptionKey, PrivacyKey) {
    unimplemented!()
}
#[must_use]
pub fn k4(key: AppKey) -> AID {
    unimplemented!()
}
#[must_use]
pub fn s1(m: &'static str) -> Salt {
    unimplemented!()
}
