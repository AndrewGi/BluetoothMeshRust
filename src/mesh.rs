use crate::bytes::ToFromBytesEndian;
use core::fmt::{Display, Error, Formatter};

#[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug)]
pub struct IVI(bool);
impl From<IVI> for bool {
    fn from(i: IVI) -> Self {
        i.0
    }
}
impl From<bool> for IVI {
    fn from(b: bool) -> Self {
        IVI(b)
    }
}
#[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug)]
pub struct CTL(bool);
impl From<CTL> for bool {
    fn from(c: CTL) -> Self {
        c.0
    }
}
impl From<bool> for CTL {
    fn from(b: bool) -> Self {
        CTL(b)
    }
}
#[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug)]
pub struct TTL(u8);

const TTL_MAX: u8 = 127;

impl TTL {
    pub fn new(v: u8) -> TTL {
        if v > TTL_MAX {
            panic!("TTL {} is bigger than max TTL {}", v, TTL_MAX);
        } else {
            TTL(v)
        }
    }
    pub fn with_flag(&self, flag: bool) -> u8 {
        self.0 | ((flag as u8) << 7)
    }
    /// returns 7 bit TTL + 1 bit bool flag from 8bit uint.
    pub fn new_with_flag(v: u8) -> (TTL, bool) {
        (TTL(v & 0x7F), v & 0x80 != 0)
    }
    pub fn should_relay(&self) -> bool {
        match self.0 {
            2..=127 => true,
            _ => false,
        }
    }
}

#[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug)]
pub struct NID(u8);

const NID_MAX: u8 = 127;

impl NID {
    pub fn new(v: u8) -> NID {
        if v > NID_MAX {
            panic!("NID {} is bigger than max NID {}", v, NID_MAX);
        } else {
            NID(v)
        }
    }
    pub fn with_flag(&self, flag: bool) -> u8 {
        self.0 | ((flag as u8) << 7)
    }

    /// returns 7 bit NID + 1 bit bool flag from 8bit uint.
    pub fn new_with_flag(v: u8) -> (NID, bool) {
        (NID(v & 0x7F), v & 0x80 != 0)
    }
}

#[derive(Default, Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug)]
pub struct U24(u32);
const U24_MAX: u32 = 16777215; // 2**24 - 1
impl Display for U24 {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), Error> {
        write!(f, "U24({})", self.0)
    }
}
impl U24 {
    pub fn new(v: u32) -> U24 {
        if v > U24_MAX {
            panic!("number {} is bigger than max U24 {}", v, U24_MAX);
        } else {
            U24(v)
        }
    }
    pub fn value(&self) -> u32 {
        self.0
    }
}
impl From<(u8, u8, u8)> for U24 {
    fn from(b: (u8, u8, u8)) -> Self {
        U24(b.0 as u32 | ((b.1 as u32) << 8) | ((b.2 as u32) << 16))
    }
}
impl ToFromBytesEndian for U24 {
    fn byte_size() -> usize {
        3 // 24 bits = 3 * 8
    }

    fn to_bytes_le(&self) -> &[u8] {
        &(self.0).to_bytes_le()[..3]
    }

    fn to_bytes_be(&self) -> &[u8] {
        &(self.0).to_bytes_be()[..3]
    }

    fn from_bytes_le(bytes: &[u8]) -> Option<Self> {
        if bytes.len() != 3 {
            None
        } else {
            Some(U24(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], 0])))
        }
    }

    fn from_bytes_be(bytes: &[u8]) -> Option<Self> {
        if bytes.len() != 3 {
            None
        } else {
            Some(U24(u32::from_be_bytes([bytes[0], bytes[1], bytes[2], 0])))
        }
    }
}
/// 24bit Sequence number
#[derive(Copy, Clone, Eq, Ord, PartialOrd, PartialEq, Debug, Hash)]
pub struct SequenceNumber(pub U24);

impl ToFromBytesEndian for SequenceNumber {
    fn byte_size() -> usize {
        3
    }

    fn to_bytes_le(&self) -> &[u8] {
        (self.0).to_bytes_le()
    }

    fn to_bytes_be(&self) -> &[u8] {
        (self.0).to_bytes_be()
    }

    fn from_bytes_le(bytes: &[u8]) -> Option<Self> {
        Some(SequenceNumber(U24::from_bytes_le(bytes)?))
    }

    fn from_bytes_be(bytes: &[u8]) -> Option<Self> {
        Some(SequenceNumber(U24::from_bytes_be(bytes)?))
    }
}
pub enum MIC {
    Big(u64),
    Small(u32),
}
impl MIC {
    pub fn mic(&self) -> u64 {
        match self {
            MIC::Big(b) => *b,
            MIC::Small(s) => *s as u64,
        }
    }
    pub fn is_big(&self) -> bool {
        match self {
            MIC::Big(_) => true,
            MIC::Small(_) => false,
        }
    }
    pub fn byte_size(&self) -> usize {
        if self.is_big() {
            8
        } else {
            4
        }
    }
}
impl ToFromBytesEndian for MIC {
    fn byte_size() -> usize {
        unimplemented!("MIC byte size can be 4 or 8 bytes")
    }

    fn to_bytes_le(&self) -> &[u8] {
        match self {
            MIC::Big(b) => b.to_bytes_le(),
            MIC::Small(s) => s.to_bytes_le(),
        }
    }

    fn to_bytes_be(&self) -> &[u8] {
        match self {
            MIC::Big(b) => b.to_bytes_be(),
            MIC::Small(s) => s.to_bytes_be(),
        }
    }

    fn from_bytes_le(bytes: &[u8]) -> Option<Self> {
        match bytes.len() {
            4 => Some(MIC::Small(u32::from_bytes_le(bytes)?)),
            8 => Some(MIC::Big(u64::from_bytes_le(bytes)?)),
            _ => None,
        }
    }

    fn from_bytes_be(bytes: &[u8]) -> Option<Self> {
        match bytes.len() {
            4 => Some(MIC::Small(u32::from_bytes_be(bytes)?)),
            8 => Some(MIC::Big(u64::from_bytes_be(bytes)?)),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ttl() {
        assert!(!TTL(0).should_relay());
        assert!(!TTL(1).should_relay());
        assert!(TTL(2).should_relay());
        assert!(TTL(65).should_relay());
        assert!(TTL(126).should_relay());
        assert!(TTL(127).should_relay())
    }
}
