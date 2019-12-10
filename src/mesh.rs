use crate::bytes::ToFromBytesEndian;

#[derive(Copy, Clone, PartialOrd, PartialEq, Debug)]
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
#[derive(Copy, Clone, PartialOrd, PartialEq, Debug)]
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
#[derive(Copy, Clone, PartialOrd, PartialEq, Debug)]
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
}

#[derive(Copy, Clone, PartialOrd, PartialEq, Debug)]
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
/// 24bit Sequence number
#[derive(Copy, Clone, PartialOrd, PartialEq, Debug)]
pub struct SequenceNumber(u32);

const SEQUENCE_MAX: u32 = 16777215; // 2**24 - 1
impl SequenceNumber {
    pub fn new(v: u32) -> SequenceNumber {
        if v > SEQUENCE_MAX {
            panic!(
                "sequence number {} is bigger than max sequence number {}",
                v, SEQUENCE_MAX
            );
        } else {
            SequenceNumber(v)
        }
    }
    pub fn value(&self) -> u32 {
        self.0
    }
}
impl ToFromBytesEndian for SequenceNumber {
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
            Some(SequenceNumber(u32::from_le_bytes([
                bytes[0], bytes[1], bytes[2], 0,
            ])))
        }
    }

    fn from_bytes_be(bytes: &[u8]) -> Option<Self> {
        if bytes.len() != 3 {
            None
        } else {
            Some(SequenceNumber(u32::from_be_bytes([
                bytes[0], bytes[1], bytes[2], 0,
            ])))
        }
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
