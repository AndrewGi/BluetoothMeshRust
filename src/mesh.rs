use crate::serializable::bytes::ToFromBytesEndian;
use core::fmt::{Display, Error, Formatter};

#[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug)]
pub struct IVI(pub bool);
impl From<IVI> for bool {
    #[must_use]
    fn from(i: IVI) -> Self {
        i.0
    }
}
impl From<bool> for IVI {
    #[must_use]
    fn from(b: bool) -> Self {
        IVI(b)
    }
}
#[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug)]
pub struct CTL(pub bool);
impl From<CTL> for bool {
    #[must_use]
    fn from(c: CTL) -> Self {
        c.0
    }
}
impl From<bool> for CTL {
    #[must_use]
    fn from(b: bool) -> Self {
        CTL(b)
    }
}
#[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug)]
pub struct TTL(u8);

const TTL_MASK: u8 = 127;

impl TTL {
    #[must_use]
    pub fn new(v: u8) -> TTL {
        assert!(
            v <= TTL_MASK,
            "TTL {} is bigger than max TTL {}",
            v,
            TTL_MASK
        );
        TTL(v)
    }
    /// Returns u8 with 7 lower bits being TTL and the 1 highest bit being a flag
    #[must_use]
    pub const fn with_flag(self, flag: bool) -> u8 {
        self.0 | ((flag as u8) << 7)
    }
    /// returns 7 bit TTL + 1 bit bool flag from 8bit uint.
    #[must_use]
    pub const fn new_with_flag(v: u8) -> (TTL, bool) {
        (TTL(v & TTL_MASK), v & !TTL_MASK != 0)
    }
    /// Creates a 7 bit TTL by masking out the 8th bit from a u8
    #[must_use]
    pub const fn from_masked_u8(v: u8) -> TTL {
        TTL(v & TTL_MASK)
    }
    #[must_use]
    pub fn should_relay(self) -> bool {
        match self.0 {
            2..=127 => true,
            _ => false,
        }
    }
}
impl Display for TTL {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), Error> {
        write!(f, "TTL({})", self.0)
    }
}
#[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug)]
pub struct NID(u8);

impl Display for NID {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), Error> {
        write!(f, "NID({})", self.0)
    }
}
const NID_MASK: u8 = 127;

impl NID {
    #[must_use]
    pub fn new(v: u8) -> NID {
        assert!(
            v <= NID_MASK,
            "NID {} is bigger than max NID {}",
            v,
            NID_MASK
        );
        NID(v)
    }
    #[must_use]
    pub const fn with_flag(self, flag: bool) -> u8 {
        self.0 | ((flag as u8) << 7)
    }
    /// Creates a 7 bit NID by masking out the 8th bit from a u8
    #[must_use]
    pub const fn from_masked_u8(v: u8) -> NID {
        NID(v & 0x7F)
    }
    /// returns 7 bit NID + 1 bit bool flag from 8bit uint.
    #[must_use]
    pub const fn new_with_flag(v: u8) -> (NID, bool) {
        (NID(v & 0x7F), v & 0x80 != 0)
    }
}

#[derive(Default, Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug)]
pub struct U24(u32);
const U24_MAX: u32 = (1_u32 << 24) - 1; // 2**24 - 1
impl Display for U24 {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), Error> {
        write!(f, "U24({})", self.0)
    }
}
impl U24 {
    #[must_use]
    pub fn new(v: u32) -> U24 {
        if v > U24_MAX {
            panic!("number {} is bigger than max U24 {}", v, U24_MAX);
        } else {
            U24(v)
        }
    }
    /// Creates a U24 by masking the 4th byte of 'v'
    #[must_use]
    pub const fn new_masked(v: u32) -> U24 {
        U24(v & U24_MAX)
    }
    #[must_use]
    pub const fn value(self) -> u32 {
        self.0
    }
}
impl From<(u8, u8, u8)> for U24 {
    #[must_use]
    fn from(b: (u8, u8, u8)) -> Self {
        U24(u32::from(b.0) | (u32::from(b.1) << 8) | (u32::from(b.2) << 16))
    }
}
impl From<U24> for (u8, u8, u8) {
    #[must_use]
    fn from(i: U24) -> Self {
        let b = i.value().to_ne_bytes();
        (b[0], b[1], b[2])
    }
}
impl ToFromBytesEndian for U24 {
    type AsBytesType = [u8; 3];

    #[must_use]
    fn to_bytes_le(&self) -> Self::AsBytesType {
        let b = (self.0).to_bytes_le();
        [b[0], b[1], b[2]]
    }

    #[must_use]
    fn to_bytes_be(&self) -> Self::AsBytesType {
        let b = (self.0).to_bytes_be();
        [b[0], b[1], b[2]]
    }

    #[must_use]
    fn from_bytes_le(bytes: &[u8]) -> Option<Self> {
        if bytes.len() == 3 {
            Some(U24(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], 0])))
        } else {
            None
        }
    }

    #[must_use]
    fn from_bytes_be(bytes: &[u8]) -> Option<Self> {
        if bytes.len() == 3 {
            Some(U24(u32::from_be_bytes([bytes[0], bytes[1], bytes[2], 0])))
        } else {
            None
        }
    }
}
#[derive(Copy, Clone, Eq, Ord, PartialOrd, PartialEq, Debug, Default, Hash)]
pub struct IVIndex(pub u32);
impl Display for IVIndex {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), Error> {
        write!(f, "IVIndex({})", self.0)
    }
}
/// 24bit Sequence number
#[derive(Copy, Clone, Eq, Ord, PartialOrd, PartialEq, Debug, Default, Hash)]
pub struct SequenceNumber(pub U24);

impl Display for SequenceNumber {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), Error> {
        write!(f, "SequenceNumber({})", (self.0).value())
    }
}
impl ToFromBytesEndian for SequenceNumber {
    type AsBytesType = [u8; 3];

    #[must_use]
    fn to_bytes_le(&self) -> Self::AsBytesType {
        (self.0).to_bytes_le()
    }

    #[must_use]
    fn to_bytes_be(&self) -> Self::AsBytesType {
        (self.0).to_bytes_be()
    }

    #[must_use]
    fn from_bytes_le(bytes: &[u8]) -> Option<Self> {
        Some(SequenceNumber(U24::from_bytes_le(bytes)?))
    }

    #[must_use]
    fn from_bytes_be(bytes: &[u8]) -> Option<Self> {
        Some(SequenceNumber(U24::from_bytes_be(bytes)?))
    }
}
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
    /// use crate::bluetooth_mesh::mesh::MIC;
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
    pub const fn max_size() -> usize {
        BIG_MIC_SIZE
    }
    /// returns the small size of a mic
    /// example:
    /// ```
    /// use bluetooth_mesh::mesh::MIC;
    /// assert_eq!(MIC::small_size(), MIC::Small(0).byte_size());
    /// ```
    #[must_use]
    pub const fn small_size() -> usize {
        SMALL_MIC_SIZE
    }
    /// returns the big size of a mic
    /// example:
    /// ```
    /// use bluetooth_mesh::mesh::MIC;
    /// assert_eq!(MIC::big_size(), MIC::Big(0).byte_size());
    /// ```
    #[must_use]
    pub const fn big_size() -> usize {
        BIG_MIC_SIZE
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

#[derive(Copy, Clone, Eq, PartialEq, Debug, Hash)]
pub struct CompanyID(u16);
impl ToFromBytesEndian for CompanyID {
    type AsBytesType = [u8; 2];

    #[must_use]
    fn to_bytes_le(&self) -> Self::AsBytesType {
        (self.0).to_bytes_le()
    }

    #[must_use]
    fn to_bytes_be(&self) -> Self::AsBytesType {
        (self.0).to_bytes_be()
    }

    #[must_use]
    fn from_bytes_le(bytes: &[u8]) -> Option<Self> {
        Some(CompanyID(u16::from_bytes_le(bytes)?))
    }

    #[must_use]
    fn from_bytes_be(bytes: &[u8]) -> Option<Self> {
        Some(CompanyID(u16::from_bytes_be(bytes)?))
    }
}
#[derive(Copy, Clone, Eq, PartialEq, Debug, Hash)]
pub struct ModelID(u16);
impl ToFromBytesEndian for ModelID {
    type AsBytesType = [u8; 2];

    #[must_use]
    fn to_bytes_le(&self) -> Self::AsBytesType {
        (self.0).to_bytes_le()
    }

    #[must_use]
    fn to_bytes_be(&self) -> Self::AsBytesType {
        (self.0).to_bytes_be()
    }

    #[must_use]
    fn from_bytes_le(bytes: &[u8]) -> Option<Self> {
        Some(ModelID(u16::from_bytes_le(bytes)?))
    }

    #[must_use]
    fn from_bytes_be(bytes: &[u8]) -> Option<Self> {
        Some(ModelID(u16::from_bytes_be(bytes)?))
    }
}
#[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Debug, Hash)]
pub struct NetworkKeyIndex(u16);
#[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Debug, Hash)]
pub struct AppKeyIndex(u16);
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ttl() {
        assert!(!TTL::new(0).should_relay());
        assert!(!TTL::new(1).should_relay());
        assert!(TTL::new(2).should_relay());
        assert!(TTL::new(65).should_relay());
        assert!(TTL::new(126).should_relay());
        assert!(TTL::new(127).should_relay())
    }
    #[test]
    #[should_panic]
    fn test_ttl_out_of_range() {
        TTL::new(128);
    }
}
