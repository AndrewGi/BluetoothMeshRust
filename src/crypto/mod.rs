//! Crypto functions (AES, ECDH) that the Mesh uses.
//! AES is primarily used in the `crypto::k_funcs` and in network/application layer encryption.
//! ECDH is used for the provisioning key exchange.
use crate::crypto::key::{Key, NetKey};
use core::convert::TryFrom;

/// Helper function to convert a 16 byte (32 character) hex string to 16 byte array.
/// Returns `None` if `hex.len() != 32` or if `hex` contains non-hex characters.
pub fn hex_16_to_array(hex: &str) -> Option<[u8; 16]> {
    if hex.len() != 32 {
        None
    } else {
        let mut out = [0_u8; 16];
        for (pos, c) in hex.chars().enumerate() {
            let value = u8::try_from(c.to_digit(16)?).ok()?;
            let byte_pos = pos / 2;
            if pos % 2 == 1 {
                out[byte_pos] |= value;
            } else {
                out[byte_pos] |= value << 4;
            }
        }
        Some(out)
    }
}

pub mod aes;
mod aes_ccm;
mod aes_cmac;
pub mod k_funcs;
pub mod key;
pub mod materials;
pub mod nonce;
#[derive(Copy, Clone, Eq, PartialEq, Debug, Hash)]
pub enum MIC {
    Big(u64),
    Small(u32),
}
const BIG_MIC_SIZE: usize = 8;
const SMALL_MIC_SIZE: usize = 4;
impl MIC {
    #[must_use]
    pub fn try_from_bytes_be(bytes: &[u8]) -> Option<MIC> {
        match bytes.len() {
            SMALL_MIC_SIZE => Some(MIC::Small(u32::from_bytes_be(bytes)?)),
            BIG_MIC_SIZE => Some(MIC::Big(u64::from_bytes_be(bytes)?)),
            _ => None,
        }
    }
    #[must_use]
    pub fn try_from_bytes_le(bytes: &[u8]) -> Option<MIC> {
        match bytes.len() {
            SMALL_MIC_SIZE => Some(MIC::Small(u32::from_bytes_le(bytes)?)),
            BIG_MIC_SIZE => Some(MIC::Big(u64::from_bytes_le(bytes)?)),
            _ => None,
        }
    }
    #[must_use]
    pub fn mic(&self) -> u64 {
        match self {
            MIC::Big(b) => *b,
            MIC::Small(s) => u64::from(*s),
        }
    }
    #[must_use]
    pub fn is_big(&self) -> bool {
        match self {
            MIC::Big(_) => true,
            MIC::Small(_) => false,
        }
    }
    /// Return the size in bytes (4 or 8) needed to represent the MIC.
    /// Depends on if the MIC is small or big
    /// ```
    /// use crate::bluetooth_mesh::crypto::MIC;
    /// assert_eq!(MIC::Big(0u64).byte_size(), 8);
    /// assert_eq!(MIC::Small(0u32).byte_size(), 4);
    /// ```
    #[must_use]
    pub fn byte_size(&self) -> usize {
        if self.is_big() {
            BIG_MIC_SIZE
        } else {
            SMALL_MIC_SIZE
        }
    }
    #[must_use]
    pub const fn max_len() -> usize {
        BIG_MIC_SIZE
    }
    /// returns the small size of a mic
    /// example:
    /// ```
    /// use crate::bluetooth_mesh::crypto::MIC;;
    /// assert_eq!(MIC::small_size(), MIC::Small(0).byte_size());
    /// ```
    #[must_use]
    pub const fn small_size() -> usize {
        SMALL_MIC_SIZE
    }
    /// returns the big size of a mic
    /// example:
    /// ```
    /// use crate::bluetooth_mesh::crypto::MIC;;
    /// assert_eq!(MIC::big_size(), MIC::Big(0).byte_size());
    /// ```
    #[must_use]
    pub const fn big_size() -> usize {
        BIG_MIC_SIZE
    }
}
impl TryFrom<&[u8]> for MIC {
    type Error = ();

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        Self::try_from_bytes_be(value).ok_or(())
    }
}
impl Display for MIC {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), Error> {
        let (name, value) = match self {
            MIC::Big(b) => ("Big", *b),
            MIC::Small(s) => ("Small", u64::from(*s)),
        };
        write!(f, "{}({})", name, value)
    }
}

/// 6 bit Application Key ID
#[derive(Clone, Copy, Debug, Hash, Eq, PartialOrd, PartialEq, Ord)]
pub struct AID(u8);
const AID_MAX: u8 = (1 << 6) - 1;

impl AID {
    /// Creates a new 6 bit `AID`
    /// # Panics
    /// Panics if `aid > AID_MAX` (64)
    pub fn new(aid: u8) -> AID {
        assert!(aid > AID_MAX);
        AID::new_masked(aid)
    }
    /// Creates a AID by masking `aid` to just 6 (lower) bits
    pub fn new_masked(aid: u8) -> AID {
        AID(aid & AID_MAX)
    }
}
#[derive(Clone, Copy, Debug, Hash, Eq, PartialOrd, PartialEq, Ord)]
pub struct AKF(bool);
impl From<bool> for AKF {
    fn from(b: bool) -> Self {
        AKF(b)
    }
}
impl From<AKF> for bool {
    fn from(a: AKF) -> Self {
        a.0
    }
}
#[derive(Debug, Copy, Clone)]
pub struct TryFromBlockError(());
const SALT_LEN: usize = 16;
#[derive(Clone, Copy, Debug, Hash, Eq, PartialOrd, PartialEq, Ord)]
pub struct Salt([u8; SALT_LEN]);

impl Salt {
    pub fn new(salt: [u8; SALT_LEN]) -> Salt {
        Salt(salt)
    }
    pub fn from_hex(hex: &str) -> Option<Salt> {
        Some(Salt::new(hex_16_to_array(hex)?))
    }
    pub fn as_key(&self) -> Key {
        Key::new(self.0)
    }
}

impl TryFrom<&[u8]> for Salt {
    type Error = TryFromBlockError;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        if value.len() != SALT_LEN {
            Err(TryFromBlockError(()))
        } else {
            let mut buf = Salt([0_u8; SALT_LEN]);
            buf.0.copy_from_slice(value);
            Ok(buf)
        }
    }
}
impl AsRef<[u8]> for Salt {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}
#[derive(Clone, Copy, Debug, Hash, Eq, PartialOrd, PartialEq, Ord)]
pub struct ProvisioningSalt(Salt);
impl ProvisioningSalt {
    pub fn as_salt(&self) -> Salt {
        self.0
    }
}
#[derive(Clone, Copy, Debug, Hash, Eq, PartialOrd, PartialEq, Ord)]
pub struct ECDHSecret(Salt);
impl ECDHSecret {
    pub fn new_bytes(bytes: [u8; SALT_LEN]) -> Self {
        Self(Salt::new(bytes))
    }
    pub fn as_salt(&self) -> Salt {
        self.0
    }
}
impl AsRef<[u8]> for ECDHSecret {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}
#[derive(Clone, Copy, Debug, Hash, Eq, PartialOrd, PartialEq, Ord)]
pub struct NetworkID(u64);
impl From<&key::NetKey> for NetworkID {
    fn from(k: &NetKey) -> Self {
        NetworkID(k3(k.key()))
    }
}
#[derive(Ord, PartialOrd, Eq, PartialEq, Copy, Clone, Debug, Hash)]
pub struct NetKeyIndex(u16);
#[derive(Ord, PartialOrd, Eq, PartialEq, Copy, Clone, Debug, Hash)]
pub struct AppKeyIndex(u16);

#[repr(u8)]
pub enum KeyRefreshPhases {
    Normal,
    First,
    Second,
    Third,
}
use crate::serializable::bytes::ToFromBytesEndian;
use core::fmt::{Display, Error, Formatter};
pub use k_funcs::{k1, k2, k3, k4, s1};
