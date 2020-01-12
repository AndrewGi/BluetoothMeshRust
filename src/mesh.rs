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
pub struct KeyRefreshFlag(pub bool);
impl From<KeyRefreshFlag> for bool {
    #[must_use]
    fn from(c: KeyRefreshFlag) -> Self {
        c.0
    }
}
impl From<bool> for KeyRefreshFlag {
    #[must_use]
    fn from(b: bool) -> Self {
        KeyRefreshFlag(b)
    }
}
#[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug)]
pub struct IVUpdateFlag(pub bool);
impl From<IVUpdateFlag> for bool {
    #[must_use]
    fn from(c: IVUpdateFlag) -> Self {
        c.0
    }
}
impl From<bool> for IVUpdateFlag {
    #[must_use]
    fn from(b: bool) -> Self {
        IVUpdateFlag(b)
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
/// 7-bit `NID` (different than `NetworkID`!!)
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
/// 24-bit Unsigned Integer. Commonly used for other 24-bit Unsigned types (`IVIndex`, `SequenceNumber`, Etc)
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
impl ToFromBytesEndian for U24 {
    type AsBytesType = [u8; 3];

    #[must_use]
    fn to_bytes_le(&self) -> Self::AsBytesType {
        let b = self.0.to_le_bytes();
        [b[0], b[1], b[2]]
    }

    #[must_use]
    fn to_bytes_be(&self) -> Self::AsBytesType {
        let b = self.0.to_be_bytes();
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
            Some(U24(u32::from_be_bytes([0, bytes[0], bytes[1], bytes[2]])))
        } else {
            None
        }
    }
}
#[derive(Copy, Clone, Eq, Ord, PartialOrd, PartialEq, Debug, Default, Hash)]
pub struct IVIndex(pub u32);
impl IVIndex {
    pub fn ivi(&self) -> IVI {
        IVI(self.0 & 1 == 1)
    }
    pub fn matching_ivi(&self, ivi: IVI) -> Option<IVIndex> {
        if self.ivi() == ivi {
            Some(*self)
        } else if self.0 == 0 {
            None
        } else {
            Some(IVIndex(self.0 - 1))
        }
    }
}

impl Display for IVIndex {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), Error> {
        write!(f, "IVIndex({})", self.0)
    }
}
impl ToFromBytesEndian for IVIndex {
    type AsBytesType = [u8; 4];

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
        Some(Self(u32::from_bytes_le(bytes)?))
    }

    #[must_use]
    fn from_bytes_be(bytes: &[u8]) -> Option<Self> {
        Some(Self(u32::from_bytes_be(bytes)?))
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
        let _ = TTL::new(128);
    }
}
