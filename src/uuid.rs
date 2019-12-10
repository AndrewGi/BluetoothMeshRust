use alloc::string::{String, ToString};
use core::convert::TryInto;
use core::fmt::{Display, Error, Formatter};

type Bytes = [u8; 16];

#[derive(Copy, Clone, Eq, PartialEq)]
pub struct UUID(Bytes);

impl UUID {
    pub fn from_fields(
        time_low: u32,
        time_mid: u16,
        time_high: u16,
        clock_seq: u16,
        node: u64,
    ) -> UUID {
        let tl = &time_low.to_be_bytes();
        let tm = &time_mid.to_be_bytes();
        let th = &time_high.to_be_bytes();
        let cs = &clock_seq.to_be_bytes();
        let nb = &node.to_be_bytes()[..6];
        // This is a dumb way of building a UUID from byte slices but it should work.
        UUID([
            tl[0], tl[1], tl[2], tl[3], tm[0], tm[1], th[0], th[1], cs[0], cs[1], nb[0], nb[1],
            nb[2], nb[3], nb[4], nb[5],
        ])
    }
    pub fn time_low(self) -> u32 {
        u32::from_be_bytes(self.0[..4].try_into().unwrap())
    }
    pub fn time_mid(self) -> u16 {
        u16::from_be_bytes(self.0[4..6].try_into().unwrap())
    }
    pub fn time_high(self) -> u16 {
        u16::from_be_bytes(self.0[6..8].try_into().unwrap())
    }
    pub fn clock_seq(self) -> u16 {
        u16::from_be_bytes(self.0[8..10].try_into().unwrap())
    }
    pub fn node(self) -> u64 {
        u64::from_be_bytes([
            self.0[10], self.0[11], self.0[12], self.0[13], self.0[14], self.0[15], 0, 0,
        ])
    }
}

pub struct UUIDFields {
    pub time_low: u32,
    pub time_mid: u16,
    pub time_hi_and_version: u16,
    pub clock_seq: u16,
    pub node: u64,
}

impl Into<UUIDFields> for UUID {
    fn into(self) -> UUIDFields {
        UUIDFields {
            time_low: self.time_low(),
            time_mid: self.time_mid(),
            time_hi_and_version: self.time_high(),
            clock_seq: self.clock_seq(),
            node: self.node(),
        }
    }
}
impl Into<UUID> for UUIDFields {
    fn into(self) -> UUID {
        UUID::from_fields(
            self.time_low,
            self.time_mid,
            self.time_hi_and_version,
            self.clock_seq,
            self.node,
        )
    }
}
impl Display for UUID {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), Error> {
        write!(
            f,
            "{:0x}-{:0x}-{:0x}-{:0x}-{:06x}",
            self.time_low(),
            self.time_mid(),
            self.time_high(),
            self.clock_seq(),
            self.node()
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_format() {
        let time_low = 0x123e4567;
        let time_mid = 0xe89b;
        let time_high = 0x12d3;
        let clock_seq = 0xa456;
        let node = 0x426655440000;
        let uuid = UUID::from_fields(time_low, time_mid, time_high, clock_seq, node);

        assert_eq!(uuid.to_string(), "123e4567-e89b-12d3-a456-426655440000");

        let fields: UUIDFields = uuid.into();
        assert_eq!(time_low, fields.time_low);
        assert_eq!(time_mid, fields.time_mid);
        assert_eq!(time_high, fields.time_hi_and_version);
        assert_eq!(clock_seq, fields.clock_seq);
        assert_eq!(node, fields.node)
    }
}
