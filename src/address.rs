use crate::serializable::bytes::ToFromBytesEndian;
use crate::uuid::UUID;
use core::convert::{TryFrom, TryInto};

/// Mesh Addresses
/// | Bits (16)             | Type          |
/// |-----------------------|---------------|
/// | 0b0000 0000 0000 0000 | Unassigned    |
/// | 0b0xxx xxxx xxxx xxxx | Unicast       |
/// | 0b10xx xxxx xxxx xxxx | Virtual       |
/// | 0b11xx xxxx xxxx xxxx | Group         |
///
/// Endian depends on layer!!
/// Little: Access/Foundation
/// Big: Everything else

const UNICAST_BIT: u16 = 0x8000;
const UNICAST_MASK: u16 = !UNICAST_BIT;

const GROUP_BIT: u16 = 0xC000;
const GROUP_MASK: u16 = !GROUP_BIT;

const VIRTUAL_BIT: u16 = 0x8000;
const VIRTUAL_MASK: u16 = GROUP_MASK;

#[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug)]
pub struct UnicastAddress(u16);
#[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug)]
pub struct GroupAddress(u16);
/// Only stores the 14 bit hash of the virtual UUID.
/// For the full 128 bit UUID, look at [`VirtualAddress`]
#[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug)]
pub struct VirtualAddressHash(u16);
/// Stores the 14 bit hash and full 128 bit virtual UUID.
#[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug)]
pub struct VirtualAddress(VirtualAddressHash, UUID);

impl UnicastAddress {
    /// Creates a Unicast address by masking any u16 into it.
    pub fn from_mask_u16(v: u16) -> UnicastAddress {
        UnicastAddress(v & UNICAST_MASK)
    }
}

impl TryFrom<u16> for UnicastAddress {
    type Error = ();

    fn try_from(v: u16) -> Result<UnicastAddress, Self::Error> {
        if v == 0 {
            Err(())
        } else if v & UNICAST_BIT == 0 {
            Ok(UnicastAddress(v))
        } else {
            Err(())
        }
    }
}

impl TryFrom<u16> for GroupAddress {
    type Error = ();

    fn try_from(v: u16) -> Result<GroupAddress, Self::Error> {
        if v & 0xC000 == 0xC000 {
            Ok(GroupAddress(v))
        } else {
            Err(())
        }
    }
}

impl TryFrom<u16> for VirtualAddressHash {
    type Error = ();
    fn try_from(v: u16) -> Result<VirtualAddressHash, Self::Error> {
        if v & 0xC000 == 0x8000 {
            Ok(VirtualAddressHash(v))
        } else {
            Err(())
        }
    }
}

impl From<UnicastAddress> for u16 {
    fn from(v: UnicastAddress) -> Self {
        v.0
    }
}
impl From<GroupAddress> for u16 {
    fn from(v: GroupAddress) -> Self {
        v.0
    }
}
impl From<VirtualAddressHash> for u16 {
    fn from(v: VirtualAddressHash) -> Self {
        v.0
    }
}
impl From<VirtualAddress> for u16 {
    fn from(v: VirtualAddress) -> Self {
        (v.0).0
    }
}
#[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug)]
pub enum Address {
    Unassigned,
    Unicast(UnicastAddress),
    Group(GroupAddress),
    Virtual(VirtualAddress),
    VirtualHash(VirtualAddressHash),
}

impl Address {
    fn is_assigned(&self) -> bool {
        match self {
            Address::Unassigned => false,
            _ => true,
        }
    }
    fn value(&self) -> u16 {
        self.into()
    }
}

impl Default for Address {
    fn default() -> Self {
        Address::Unassigned
    }
}

impl From<u16> for Address {
    fn from(v: u16) -> Address {
        if v == 0 {
            Address::Unassigned
        } else if v & GROUP_BIT == 0 {
            Address::Unicast(UnicastAddress(v))
        } else if v & GROUP_BIT == GROUP_BIT {
            Address::Group(GroupAddress(v))
        } else {
            Address::VirtualHash(VirtualAddressHash(v))
        }
    }
}

impl From<&Address> for u16 {
    fn from(v: &Address) -> Self {
        match v {
            Address::Unassigned => 0,
            Address::Unicast(u) => u.0,
            Address::Group(g) => g.0,
            Address::Virtual(v) => (v.0).0,
            Address::VirtualHash(vh) => vh.0,
        }
    }
}

impl TryFrom<&Address> for UnicastAddress {
    type Error = ();

    fn try_from(value: &Address) -> Result<Self, Self::Error> {
        match value {
            Address::Unicast(u) => Ok(*u),
            _ => Err(()),
        }
    }
}
impl TryFrom<&Address> for VirtualAddressHash {
    type Error = ();

    fn try_from(value: &Address) -> Result<Self, Self::Error> {
        match value {
            Address::VirtualHash(h) => Ok(*h),
            _ => Err(()),
        }
    }
}
impl TryFrom<&Address> for VirtualAddress {
    type Error = ();

    fn try_from(value: &Address) -> Result<Self, Self::Error> {
        match value {
            Address::Virtual(v) => Ok(*v),
            _ => Err(()),
        }
    }
}
impl TryFrom<&Address> for GroupAddress {
    type Error = ();

    fn try_from(value: &Address) -> Result<Self, Self::Error> {
        match value {
            Address::Group(g) => Ok(*g),
            _ => Err(()),
        }
    }
}
impl ToFromBytesEndian for Address {
    type AsBytesType = [u8; 2];

    fn to_bytes_le(&self) -> Self::AsBytesType {
        match self {
            Address::Unassigned => 0u16.to_bytes_le(),
            Address::Unicast(u) => (u.0).to_bytes_le(),
            Address::Group(g) => (g.0).to_bytes_le(),
            Address::Virtual(v) => ((v.0).0).to_bytes_le(),
            Address::VirtualHash(h) => (h.0).to_bytes_le(),
        }
    }

    fn to_bytes_be(&self) -> Self::AsBytesType {
        match self {
            Address::Unassigned => 0u16.to_bytes_be(),
            Address::Unicast(u) => (u.0).to_bytes_be(),
            Address::Group(g) => (g.0).to_bytes_be(),
            Address::Virtual(v) => ((v.0).0).to_bytes_be(),
            Address::VirtualHash(h) => (h.0).to_bytes_be(),
        }
    }

    fn from_bytes_le(bytes: &[u8]) -> Option<Self> {
        Some(u16::from_bytes_le(bytes)?.into())
    }

    fn from_bytes_be(bytes: &[u8]) -> Option<Self> {
        Some(u16::from_bytes_be(bytes)?.into())
    }
}

impl ToFromBytesEndian for UnicastAddress {
    type AsBytesType = [u8; 2];

    fn to_bytes_le(&self) -> Self::AsBytesType {
        (self.0).to_bytes_le()
    }

    fn to_bytes_be(&self) -> Self::AsBytesType {
        (self.0).to_bytes_be()
    }

    fn from_bytes_le(bytes: &[u8]) -> Option<Self> {
        u16::from_bytes_le(bytes)?.try_into().ok()
    }

    fn from_bytes_be(bytes: &[u8]) -> Option<Self> {
        u16::from_bytes_be(bytes)?.try_into().ok()
    }
}

impl ToFromBytesEndian for VirtualAddressHash {
    type AsBytesType = [u8; 2];

    fn to_bytes_le(&self) -> Self::AsBytesType {
        (self.0).to_bytes_le()
    }

    fn to_bytes_be(&self) -> Self::AsBytesType {
        (self.0).to_bytes_be()
    }

    fn from_bytes_le(bytes: &[u8]) -> Option<Self> {
        u16::from_bytes_le(bytes)?.try_into().ok()
    }

    fn from_bytes_be(bytes: &[u8]) -> Option<Self> {
        u16::from_bytes_be(bytes)?.try_into().ok()
    }
}
impl ToFromBytesEndian for GroupAddress {
    type AsBytesType = [u8; 2];

    fn to_bytes_le(&self) -> Self::AsBytesType {
        (self.0).to_bytes_le()
    }

    fn to_bytes_be(&self) -> Self::AsBytesType {
        (self.0).to_bytes_be()
    }

    fn from_bytes_le(bytes: &[u8]) -> Option<Self> {
        u16::from_bytes_le(bytes)?.try_into().ok()
    }

    fn from_bytes_be(bytes: &[u8]) -> Option<Self> {
        u16::from_bytes_be(bytes)?.try_into().ok()
    }
}
