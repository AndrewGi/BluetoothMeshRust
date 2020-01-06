use crate::crypto::aes::AESCipher;
use crate::crypto::key::{AppKey, EncryptionKey, Key, PrivacyKey, ZERO_KEY};
use crate::crypto::{Salt, AID};
use crate::mesh::NID;
use core::convert::TryInto;

/// k1 function from Mesh Core v1.0. N==`bytes` and P==`extra`.
#[must_use]
pub fn k1(key: &Key, salt: Salt, extra: &[u8]) -> Key {
    let t = AESCipher::from(salt).cmac(key.as_ref());
    AESCipher::from(t).cmac(extra)
}
pub fn k2(key: &Key, p: impl AsRef<[u8]>) -> (NID, EncryptionKey, PrivacyKey) {
    k2_bytes(key, p.as_ref())
}
#[must_use]
pub fn k2_bytes(n: &Key, p: &[u8]) -> (NID, EncryptionKey, PrivacyKey) {
    assert!(!p.is_empty(), "p must have at least one byte");
    let t = AESCipher::from(SMK2).cmac(n.as_ref());
    let cipher = AESCipher::from(t);
    let t_1 = cipher.cmac_slice(&[p, &[0x01]]);
    let t_2 = cipher.cmac_slice(&[t_1.as_ref(), p, &[0x02]]);
    let t_3 = cipher.cmac_slice(&[t_2.as_ref(), p, &[0x03]]);

    (
        NID::new(t_1.as_ref()[15] & 0x7F),
        EncryptionKey::new(t_2),
        PrivacyKey::new(t_3),
    )
}
#[must_use]
pub fn k3(key: &Key) -> u64 {
    let t = AESCipher::from(SMK3).cmac(key.as_ref());
    u64::from_be_bytes(
        AESCipher::from(t).cmac(b"id64\x01".as_ref()).as_ref()[8..]
            .try_into()
            .expect("aes_cmac returns 16 bytes and the last 8 get turned into a u64"),
    )
}
#[must_use]
pub fn k4(key: &AppKey) -> AID {
    let t = AESCipher::from(SMK4).cmac(key.as_ref().as_ref());
    AID(AESCipher::from(t).cmac(b"id6\x01").as_ref()[15] & 0x3F)
}

/// Calculates Bluetooth Mesh's `s1` on bytes. Common values are precomputed and
/// hardcore to avoid recalculating `s1` unneededly.
#[must_use]
pub fn s1(m: impl AsRef<[u8]>) -> Salt {
    s1_bytes(m.as_ref())
}
/// `VTAD == s1("vtad")`
pub const VTAD: Salt = Salt([
    0xce, 0xf7, 0xfa, 0x9d, 0xc4, 0x7b, 0xaf, 0x5d, 0xaa, 0xee, 0xd1, 0x94, 0x6, 0x9, 0x4f, 0x37,
]);
/// `PRDK == s1("prdk")`
pub const PRDK: Salt = Salt([
    234, 68, 121, 239, 105, 21, 232, 251, 128, 106, 70, 188, 231, 231, 229, 72,
]);
/// `SMK1 == s1("smk1")`
pub const SMK1: Salt = Salt([
    0xaa, 0x20, 0x18, 0xc6, 0x98, 0xe8, 0xb2, 0xef, 0x77, 0x75, 0x37, 0x19, 0xe9, 0xf1, 0xa8, 0x4,
]);
/// `SMK2 == s1("smk2")`
pub const SMK2: Salt = Salt([
    0x4f, 0x90, 0x48, 0xc, 0x18, 0x71, 0xbf, 0xbf, 0xfd, 0x16, 0x97, 0x1f, 0x4d, 0x8d, 0x10, 0xb1,
]);

/// `SMK3 == s1("smk3")`
pub const SMK3: Salt = Salt([
    0x0, 0x36, 0x44, 0x35, 0x3, 0xf1, 0x95, 0xcc, 0x8a, 0x71, 0x6e, 0x13, 0x62, 0x91, 0xc3, 0x2,
]);
/// `SMK4 == s1("smk4")`
pub const SMK4: Salt = Salt([
    0xe, 0x9a, 0xc1, 0xb7, 0xce, 0xfa, 0x66, 0x87, 0x4c, 0x97, 0xee, 0x54, 0xac, 0x5f, 0x49, 0xbe,
]);
#[must_use]
pub fn s1_bytes(m: &[u8]) -> Salt {
    AESCipher::new(ZERO_KEY).cmac(m).as_salt()
}
pub fn id128(n: &Key, s: impl AsRef<[u8]>) -> Key {
    id128_bytes(n, s.as_ref())
}
#[must_use]
pub fn id128_bytes(n: &Key, s: &[u8]) -> Key {
    let salt = s1_bytes(s);
    k1(&salt.as_key(), n.as_salt(), b"id128\x01")
}

/// Tests based on Mesh Core v1.0 Sample Data.
#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::hex_16_to_array;
    use crate::crypto::key::NetKey;

    fn sample_net_key() -> NetKey {
        NetKey::from_hex("f7a2a44f8e8a8029064f173ddc1e2b00").unwrap()
    }

    #[test]
    fn test_s1() {
        assert_eq!(
            s1("test"),
            Salt::from_hex("b73cefbd641ef2ea598c2b6efb62f79c").unwrap()
        );
    }

    #[test]
    fn test_s1_precomputed() {
        assert_eq!(s1("prkd"), PRDK);
        assert_eq!(s1("vtad"), VTAD);
        assert_eq!(s1("smk1"), SMK1);
        assert_eq!(s1("smk2"), SMK2);
        assert_eq!(s1("smk3"), SMK3);
        assert_eq!(s1("smk4"), SMK4);
    }

    #[test]
    fn test_k1() {
        let key = Key::from_hex("3216d1509884b533248541792b877f98").unwrap();
        let salt = Salt::from_hex("2ba14ffa0df84a2831938d57d276cab4").unwrap();
        let p = hex_16_to_array("5a09d60797eeb4478aada59db3352a0d").unwrap();
        let expected = Key::from_hex("f6ed15a8934afbe7d83e8dcb57fcf5d7").unwrap();
        assert_eq!(k1(&key, salt, &p[..]), expected);
    }

    #[test]
    fn test_k2_friendship() {
        let nid = NID::new(0x7F);
        let encryption_key = EncryptionKey::from_hex("9f589181a0f50de73c8070c7a6d27f46").unwrap();
        let privacy_key = PrivacyKey::from_hex("4c715bd4a64b938f99b453351653124f").unwrap();
        assert_eq!(
            k2(&sample_net_key().key(), b"\x00"),
            (nid, encryption_key, privacy_key)
        );
    }
    #[test]
    fn test_k2_master() {
        let nid = NID::new(0x73);
        let encryption_key = EncryptionKey::from_hex("11efec0642774992510fb5929646df49").unwrap();
        let privacy_key = PrivacyKey::from_hex("d4d7cc0dfa772d836a8df9df5510d7a7").unwrap();
        assert_eq!(
            k2(
                &sample_net_key().key(),
                b"\x01\x02\x03\x04\x05\x06\x07\x08\x09"
            ),
            (nid, encryption_key, privacy_key)
        );
    }

    #[test]
    fn test_k3() {
        let key = Key::from_hex("f7a2a44f8e8a8029064f173ddc1e2b00").unwrap();
        assert_eq!(0xff046958233db014u64, k3(&key));
    }
    #[test]
    fn test_k4() {
        let app_key = AppKey::from_hex("3216d1509884b533248541792b877f98").unwrap();
        assert_eq!(AID(0x38), k4(&app_key))
    }
}
