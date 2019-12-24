use crate::crypto::key::{AppKey, EncryptionKey, Key, NetKey, PrivacyKey};
use crate::crypto::{ECDHSecret, NetworkID, Salt, AID};
use crate::mesh::NID;

pub fn k1(secret: ECDHSecret, salt: Salt, extra: &'static str) -> Key {
    unimplemented!()
}
pub fn id128(n: Key, s: &'static str) {
    unimplemented!()
}
pub fn k3(key: NetKey) -> NetworkID {
    unimplemented!()
}
pub fn k2(key: NetKey) -> (NID, EncryptionKey, PrivacyKey) {
    unimplemented!()
}
pub fn k4(key: AppKey) -> AID {
    unimplemented!()
}
pub fn s1(m: &'static [u8]) -> Salt {}
