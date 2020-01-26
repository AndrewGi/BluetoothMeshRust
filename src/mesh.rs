//! Common Bluetooth Mesh Objects/Structures.
use crate::serializable::bytes::ToFromBytesEndian;
use core::convert::TryFrom;
use core::fmt::{Display, Error, Formatter};
use core::time;

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
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
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
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct TTL(u8);

const TTL_MASK: u8 = 127;
const TTL_MAX: u8 = 0xFF;
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
#[derive(Copy, Clone, PartialOrd, PartialEq, Ord, Eq, Hash, Debug)]
pub struct TTLConversationError(());
impl TryFrom<u8> for TTL {
    type Error = TTLConversationError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        if value > TTL_MAX {
            Err(TTLConversationError(()))
        } else {
            Ok(TTL(value))
        }
    }
}
impl From<TTL> for u8 {
    fn from(ttl: TTL) -> Self {
        ttl.0
    }
}
impl Display for TTL {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), Error> {
        write!(f, "TTL({})", self.0)
    }
}
/// 7-bit `NID` (different than `NetworkID`!!)
#[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct NID(u8);

impl Display for NID {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), Error> {
        write!(f, "{}", self.0)
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
impl From<NID> for u8 {
    fn from(n: NID) -> Self {
        n.0
    }
}
/// 24-bit Unsigned Integer. Commonly used for other 24-bit Unsigned types (`IVIndex`, `SequenceNumber`, Etc)
#[derive(Default, Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
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
    #[must_use]
    pub const fn max_value() -> U24 {
        U24(U24_MAX)
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
        [b[2], b[1], b[0]]
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
            Some(U24(u32::from_be_bytes([0, bytes[2], bytes[1], bytes[0]])))
        } else {
            None
        }
    }
}
impl From<U24> for u32 {
    fn from(u: U24) -> Self {
        u.0
    }
}
#[derive(Copy, Clone, Eq, Ord, PartialOrd, PartialEq, Debug, Default, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct IVIndex(pub u32);
impl IVIndex {
    pub fn ivi(&self) -> IVI {
        IVI(self.0 & 1 == 1)
    }
    pub fn next(&self) -> Option<IVIndex> {
        self.0.checked_add(1).map(IVIndex)
    }
    pub fn prev(&self) -> Option<IVIndex> {
        self.0.checked_sub(1).map(IVIndex)
    }
    /// Returns an IVIndex matching `IVI` and `IVUpdateFlag`. Will return `None` if there is no
    /// `self.next()` or `self.prev()`.
    /// # Example
    /// ```
    /// use bluetooth_mesh::mesh::{IVIndex, IVI, IVUpdateFlag};
    /// assert!(IVIndex(0).matching_flags(IVI(true), IVUpdateFlag(false)).is_none());
    /// assert!(IVIndex(u32::max_value()).matching_flags(IVI(false), IVUpdateFlag(true)).is_none());
    /// assert_eq!(IVIndex(2).matching_flags(IVI(true), IVUpdateFlag(false)), Some(IVIndex(1)));
    /// ```
    pub fn matching_flags(&self, ivi: IVI, update: IVUpdateFlag) -> Option<IVIndex> {
        if self.ivi() == ivi {
            Some(*self)
        } else {
            if bool::from(update) {
                self.next()
            } else {
                self.prev()
            }
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
/// 24-bit Sequence number. Sent with each Network PDU. Each element has their own Sequence Number.
#[derive(Copy, Clone, Eq, Ord, PartialOrd, PartialEq, Debug, Default, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct SequenceNumber(pub U24);
impl SequenceNumber {
    pub fn next(&self) -> SequenceNumber {
        assert!(self.0.value() <= U24_MAX);
        SequenceNumber(U24((self.0).0 + 1))
    }
}
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

/// 16-bit Bluetooth Company Identifier. Companies are assigned unique Company Identifiers to
/// Bluetooth SIG members requesting them. [See here for more](https://www.bluetooth.com/specifications/assigned-numbers/company-identifiers/)
#[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Debug, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct CompanyID(pub u16);
impl CompanyID {
    /// Return the length in bytes of `CompanyID` (2-bytes, 16-bits)
    pub const fn byte_len() -> usize {
        2
    }
}
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
#[derive(Copy, Clone, Eq, PartialEq, Debug, Hash, Ord, PartialOrd)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct ModelID(pub u16);
impl ModelID {
    pub const fn byte_len() -> usize {
        2
    }
}
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
pub struct KeyIndexConversationError(());
const KEY_INDEX_MAX: u16 = (1 << 12) - 1;
/// 12-bit KeyIndex
#[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Debug, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct KeyIndex(u16);
impl KeyIndex {
    /// # Panics
    /// Panics if `key > KEY_INDEX_MAX`.
    pub fn new(key_index: u16) -> Self {
        match Self::try_from(key_index) {
            Ok(i) => i,
            Err(_) => panic!("key index too high"),
        }
    }
    pub fn new_masked(key_index: u16) -> Self {
        KeyIndex(key_index & KEY_INDEX_MAX)
    }
}
impl TryFrom<u16> for KeyIndex {
    type Error = KeyIndexConversationError;

    fn try_from(value: u16) -> Result<Self, Self::Error> {
        if value > KEY_INDEX_MAX {
            Err(KeyIndexConversationError(()))
        } else {
            Ok(KeyIndex(value))
        }
    }
}
impl From<KeyIndex> for u16 {
    fn from(i: KeyIndex) -> Self {
        i.0
    }
}
/// 12-bit NetKeyIndex
#[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Debug, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct NetKeyIndex(pub KeyIndex);
/// 12-bit AppKeyIndex
#[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Debug, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct AppKeyIndex(pub KeyIndex);

#[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Debug, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct ElementIndex(pub u8);
impl ElementIndex {
    #[must_use]
    pub fn is_primary(&self) -> bool {
        self.0 == 0
    }
}
#[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Debug, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct ElementCount(pub u8);
const COUNT_MAX: u8 = 0b111;
/// 3-bit Transit Count,
#[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Debug, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct TransmitCount(u8);

impl TransmitCount {
    /// # Panics
    /// Panics if `count > COUNT_MAX`,
    pub fn new(count: u8) -> Self {
        assert!(count <= COUNT_MAX);
        Self(count)
    }
}
impl From<TransmitCount> for u8 {
    fn from(count: TransmitCount) -> Self {
        count.0
    }
}
const STEPS_MAX: u8 = (1u8 << 5) - 1;
/// 5-bit Transmit Interval Steps
#[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Debug, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct TransmitSteps(u8);

impl TransmitSteps {
    /// # Panics
    /// Panics if `steps > STEPS_MAX`.
    pub fn new(steps: u8) -> Self {
        assert!(steps <= STEPS_MAX);
        Self(steps)
    }
    pub fn to_milliseconds(&self) -> u32 {
        (u32::from(self.0) + 1) * 50
    }
    pub fn to_duration(&self) -> time::Duration {
        time::Duration::from_millis(self.to_milliseconds().into())
    }
}

impl From<TransmitSteps> for u8 {
    fn from(steps: TransmitSteps) -> Self {
        steps.0
    }
}
#[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Debug, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct TransmitInterval {
    pub count: TransmitCount,
    pub steps: TransmitSteps,
}
impl TransmitInterval {
    pub fn new(count: TransmitCount, steps: TransmitSteps) -> Self {
        Self { count, steps }
    }
}
impl From<TransmitInterval> for u8 {
    fn from(interval: TransmitInterval) -> Self {
        u8::from(interval.count) | (u8::from(interval.steps) << 3)
    }
}
impl From<u8> for TransmitInterval {
    fn from(b: u8) -> Self {
        Self::new(
            TransmitCount::new(b & COUNT_MAX),
            TransmitSteps::new(b >> 3),
        )
    }
}
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
