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

pub enum MIC {
    Big(u32),
    Small(u16),
}
impl MIC {
    pub fn mic(&self) -> u32 {
        match self {
            MIC::Big(b) => *b,
            MIC::Small(s) => *s as u32,
        }
    }
    pub fn byte_size(&self) -> u8 {
        if self.is_big() {
            4
        } else {
            2
        }
    }
    pub fn is_big(&self) -> bool {
        match self {
            MIC::Big(_) => true,
            MIC::Small(_) => false,
        }
    }
}
