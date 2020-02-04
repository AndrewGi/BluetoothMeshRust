//! Crypto Keys uses for Mesh Security.
use crate::crypto::k_funcs::{k1, s1};
use crate::crypto::{hex_16_to_array, ECDHSecret, NetworkID, ProvisioningSalt, Salt, AID, AKF};
use crate::random::Randomizable;
use crate::{mesh, random};
use core::convert::{TryFrom, TryInto};
use core::fmt::{Error, Formatter, LowerHex, UpperHex};
use core::str::FromStr;

pub const KEY_LEN: usize = 16;

/// 128-bit AES Key.
#[derive(Clone, Copy, Debug, Hash, Eq, PartialOrd, PartialEq, Ord)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Key([u8; KEY_LEN]);
pub const ZERO_KEY: Key = Key([0_u8; KEY_LEN]);

impl Key {
    #[must_use]
    pub fn new(key_bytes: [u8; KEY_LEN]) -> Key {
        Key(key_bytes)
    }
    pub fn from_hex(hex: &str) -> Option<Key> {
        Some(Key::new(hex_16_to_array(hex)?))
    }
    pub fn as_salt(&self) -> Salt {
        Salt(self.0)
    }
}
impl random::Randomizable for Key {
    fn random_secure() -> Self {
        let mut out = [0_u8; KEY_LEN];
        random::secure_random_fill_bytes(&mut out[..]);
        Self::new(out)
    }
}
impl TryFrom<&[u8]> for Key {
    type Error = core::array::TryFromSliceError;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        Ok(Key::new(value.try_into()?))
    }
}

impl AsRef<[u8]> for Key {
    #[must_use]
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl UpperHex for Key {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), Error> {
        for &b in &self.0 {
            write!(f, "{:0X}", b)?;
        }
        Ok(())
    }
}
impl LowerHex for Key {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), Error> {
        for &b in &self.0 {
            write!(f, "{:0x}", b)?;
        }
        Ok(())
    }
}
#[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Debug, Hash)]
pub struct KeyError(());
impl FromStr for Key {
    type Err = KeyError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(Key(mesh::bytes_str_to_buf(s).ok_or(KeyError(()))?))
    }
}
#[derive(Clone, Copy, Debug, Hash, Eq, PartialOrd, PartialEq, Ord)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct NetKey(Key);

impl NetKey {
    #[must_use]
    pub fn new_bytes(key_bytes: [u8; KEY_LEN]) -> Self {
        Self::new(Key(key_bytes))
    }
    #[must_use]
    pub fn new(key: Key) -> Self {
        Self(key)
    }
    #[must_use]
    pub fn from_hex(hex: &str) -> Option<Self> {
        Some(Self::new_bytes(hex_16_to_array(hex)?))
    }
    pub const fn key(&self) -> &Key {
        &self.0
    }
    /// Derives `IdentityKey` from `self` by using `crypto::k1`.
    #[must_use]
    pub fn derive_identity_key(&self) -> IdentityKey {
        self.into()
    }
    /// Derives `BeaconKey` from `self` by using `crypto::k1`.
    #[must_use]
    pub fn derive_beacon_key(&self) -> BeaconKey {
        self.into()
    }
    /// Derives `NetworkID` from `self` by using `crypto::k3`.
    #[must_use]
    pub fn derive_network_id(&self) -> NetworkID {
        self.into()
    }
}

impl TryFrom<&[u8]> for NetKey {
    type Error = core::array::TryFromSliceError;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        Ok(NetKey::new(value.try_into()?))
    }
}
impl From<Key> for NetKey {
    fn from(k: Key) -> Self {
        Self(k)
    }
}
impl Randomizable for NetKey {
    fn random_secure() -> Self {
        Self(Key::random_secure())
    }
}
#[derive(Clone, Copy, Debug, Hash, Eq, PartialOrd, PartialEq, Ord)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct IdentityKey(Key);

impl IdentityKey {
    #[must_use]
    pub fn new_bytes(key_bytes: [u8; KEY_LEN]) -> Self {
        Self::new(Key(key_bytes))
    }
    #[must_use]
    pub fn new(key: Key) -> Self {
        Self(key)
    }
    #[must_use]
    pub fn from_hex(hex: &str) -> Option<Self> {
        Some(Self::new_bytes(hex_16_to_array(hex)?))
    }
    #[must_use]
    pub const fn key(&self) -> Key {
        self.0
    }
}
impl From<&NetKey> for IdentityKey {
    fn from(k: &NetKey) -> Self {
        let salt = s1("nkik");
        const P: &str = "id128\x01";
        k1(k.key(), salt, P.as_bytes()).into()
    }
}
impl TryFrom<&[u8]> for IdentityKey {
    type Error = core::array::TryFromSliceError;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        Ok(IdentityKey::new(value.try_into()?))
    }
}

impl From<Key> for IdentityKey {
    fn from(k: Key) -> Self {
        Self(k)
    }
}
#[derive(Clone, Copy, Debug, Hash, Eq, PartialOrd, PartialEq, Ord)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct BeaconKey(Key);
impl BeaconKey {
    #[must_use]
    pub fn new_bytes(key_bytes: [u8; KEY_LEN]) -> Self {
        Self::new(Key(key_bytes))
    }
    #[must_use]
    pub fn new(key: Key) -> Self {
        Self(key)
    }
    #[must_use]
    pub fn from_hex(hex: &str) -> Option<Self> {
        Some(Self::new_bytes(hex_16_to_array(hex)?))
    }
    #[must_use]
    pub const fn key(&self) -> Key {
        self.0
    }
}
impl From<&NetKey> for BeaconKey {
    fn from(k: &NetKey) -> Self {
        let salt = s1("nkbk");
        const P: &str = "id128\x01";
        k1(k.key(), salt, P.as_bytes()).into()
    }
}
impl TryFrom<&[u8]> for BeaconKey {
    type Error = core::array::TryFromSliceError;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        Ok(BeaconKey::new(value.try_into()?))
    }
}
impl From<Key> for BeaconKey {
    fn from(k: Key) -> Self {
        Self(k)
    }
}
#[derive(Clone, Copy, Debug, Hash, Eq, PartialOrd, PartialEq, Ord)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct EncryptionKey(Key);

impl EncryptionKey {
    #[must_use]
    pub fn new_bytes(key_bytes: [u8; KEY_LEN]) -> EncryptionKey {
        Self::new(Key(key_bytes))
    }
    #[must_use]
    pub fn new(key: Key) -> EncryptionKey {
        EncryptionKey(key)
    }
    #[must_use]
    pub fn from_hex(hex: &str) -> Option<Self> {
        Some(Self::new_bytes(hex_16_to_array(hex)?))
    }
    #[must_use]
    pub const fn key(&self) -> Key {
        self.0
    }
}
impl TryFrom<&[u8]> for EncryptionKey {
    type Error = core::array::TryFromSliceError;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        Ok(EncryptionKey::new(value.try_into()?))
    }
}
impl From<Key> for EncryptionKey {
    fn from(k: Key) -> Self {
        Self(k)
    }
}
#[derive(Clone, Copy, Debug, Hash, Eq, PartialOrd, PartialEq, Ord)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct PrivacyKey(Key);

impl PrivacyKey {
    #[must_use]
    pub fn new_bytes(key_bytes: [u8; KEY_LEN]) -> Self {
        Self::new(Key(key_bytes))
    }
    #[must_use]
    pub fn new(key: Key) -> Self {
        Self(key)
    }
    #[must_use]
    pub fn from_hex(hex: &str) -> Option<Self> {
        Some(Self::new_bytes(hex_16_to_array(hex)?))
    }
    #[must_use]
    pub const fn key(&self) -> Key {
        self.0
    }
}
impl TryFrom<&[u8]> for PrivacyKey {
    type Error = core::array::TryFromSliceError;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        Ok(PrivacyKey::new(value.try_into()?))
    }
}
impl From<Key> for PrivacyKey {
    fn from(k: Key) -> Self {
        Self(k)
    }
}
#[derive(Clone, Copy, Debug, Hash, Eq, PartialOrd, PartialEq, Ord)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct DevKey(Key);

impl DevKey {
    #[must_use]
    pub fn new_bytes(key_bytes: [u8; KEY_LEN]) -> Self {
        Self::new(Key(key_bytes))
    }
    #[must_use]
    pub fn new(key: Key) -> Self {
        Self(key)
    }
    #[must_use]
    pub fn from_hex(hex: &str) -> Option<Self> {
        Some(Self::new_bytes(hex_16_to_array(hex)?))
    }
    #[must_use]
    pub fn from_salt_and_secret(salt: ProvisioningSalt, secret: ECDHSecret) -> Self {
        Self::new(super::k1(&salt.0.as_key(), secret.as_salt(), b"prdk"))
    }
    #[must_use]
    pub fn key(&self) -> Key {
        self.0
    }
    #[must_use]
    pub const fn akf() -> AKF {
        AKF(false)
    }
}
impl TryFrom<&[u8]> for DevKey {
    type Error = core::array::TryFromSliceError;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        Ok(DevKey::new(value.try_into()?))
    }
}

impl From<Key> for DevKey {
    fn from(k: Key) -> Self {
        Self(k)
    }
}
impl Randomizable for DevKey {
    fn random_secure() -> Self {
        Self(Key::random_secure())
    }
}
#[derive(Clone, Copy, Debug, Hash, Eq, PartialOrd, PartialEq, Ord)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct AppKey(Key);

impl AppKey {
    #[must_use]
    pub fn new_bytes(key_bytes: [u8; KEY_LEN]) -> Self {
        Self::new(Key(key_bytes))
    }
    #[must_use]
    pub fn new(key: Key) -> Self {
        Self(key)
    }
    #[must_use]
    pub fn from_hex(hex: &str) -> Option<Self> {
        Some(Self::new_bytes(hex_16_to_array(hex)?))
    }
    #[must_use]
    pub fn aid(&self) -> AID {
        super::k4(self)
    }
    #[must_use]
    pub const fn key(&self) -> Key {
        self.0
    }
    #[must_use]
    pub const fn akf() -> AKF {
        AKF(true)
    }
}

impl TryFrom<&[u8]> for AppKey {
    type Error = core::array::TryFromSliceError;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        Ok(AppKey::new(value.try_into()?))
    }
}
impl From<Key> for AppKey {
    fn from(k: Key) -> Self {
        Self(k)
    }
}
impl Randomizable for AppKey {
    fn random_secure() -> Self {
        Self(Key::random_secure())
    }
}
impl From<NetKey> for Key {
    #[must_use]
    fn from(k: NetKey) -> Self {
        k.key().clone()
    }
}
impl From<AppKey> for Key {
    #[must_use]
    fn from(k: AppKey) -> Self {
        k.key()
    }
}
impl From<IdentityKey> for Key {
    #[must_use]
    fn from(k: IdentityKey) -> Self {
        k.key()
    }
}

impl From<BeaconKey> for Key {
    #[must_use]
    fn from(k: BeaconKey) -> Self {
        k.key()
    }
}

impl From<EncryptionKey> for Key {
    #[must_use]
    fn from(k: EncryptionKey) -> Self {
        k.key()
    }
}
impl From<DevKey> for Key {
    #[must_use]
    fn from(k: DevKey) -> Self {
        k.key()
    }
}

impl AsRef<Key> for AppKey {
    fn as_ref(&self) -> &Key {
        &self.0
    }
}
impl AsRef<Key> for DevKey {
    #[must_use]
    fn as_ref(&self) -> &Key {
        &self.0
    }
}
impl AsRef<Key> for IdentityKey {
    #[must_use]
    fn as_ref(&self) -> &Key {
        &self.0
    }
}
impl AsRef<Key> for BeaconKey {
    #[must_use]
    fn as_ref(&self) -> &Key {
        &self.0
    }
}
impl AsRef<Key> for PrivacyKey {
    #[must_use]
    fn as_ref(&self) -> &Key {
        &self.0
    }
}
impl AsRef<Key> for EncryptionKey {
    #[must_use]
    fn as_ref(&self) -> &Key {
        &self.0
    }
}
