use crate::bytes::ToFromBytesEndian;
use crate::uuid::UUID;
use core::convert::{TryFrom, TryInto};

#[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq)]
pub struct UnicastAddress(u16);
#[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq)]
pub struct GroupAddress(u16);
#[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq)]
pub struct VirtualAddressHash(u16);
#[derive(Copy, Clone)]
pub struct VirtualAddress(VirtualAddressHash, UUID);

impl TryFrom<u16> for UnicastAddress {
    type Error = ();

    fn try_from(v: u16) -> Result<UnicastAddress, Self::Error> {
        if v == 0 {
            Err(())
        } else if v & 0x8000 == 0 {
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
#[derive(Copy, Clone)]
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
    fn value(self) -> u16 {
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
        } else if v & 0x8000 == 0 {
            Address::Unicast(UnicastAddress(v))
        } else if v & 0xC000 == 0xC000 {
            Address::Group(GroupAddress(v))
        } else {
            Address::VirtualHash(VirtualAddressHash(v))
        }
    }
}

impl From<Address> for u16 {
    fn from(v: Address) -> Self {
        match v {
            Address::Unassigned => 0,
            Address::Unicast(u) => u.into(),
            Address::Group(g) => g.into(),
            Address::Virtual(v) => v.into(),
            Address::VirtualHash(vh) => vh.into(),
        }
    }
}

impl ToFromBytesEndian for Address {
    fn byte_size() -> usize {
        2
    }

    fn to_bytes_le(&self) -> &[u8] {
        match self {
            Address::Unassigned => 0u16.to_bytes_le(),
            Address::Unicast(u) => (u.0).to_bytes_le(),
            Address::Group(g) => (g.0).to_bytes_le(),
            Address::Virtual(v) => ((v.0).0).to_bytes_le(),
            Address::VirtualHash(h) => (h.0).to_bytes_le(),
        }
    }

    fn to_bytes_be(&self) -> &[u8] {
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
    fn byte_size() -> usize {
        2
    }

    fn to_bytes_le(&self) -> &[u8] {
        (self.0).to_bytes_le()
    }

    fn to_bytes_be(&self) -> &[u8] {
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
    fn byte_size() -> usize {
        2
    }

    fn to_bytes_le(&self) -> &[u8] {
        (self.0).to_bytes_le()
    }

    fn to_bytes_be(&self) -> &[u8] {
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
    fn byte_size() -> usize {
        2
    }

    fn to_bytes_le(&self) -> &[u8] {
        (self.0).to_bytes_le()
    }

    fn to_bytes_be(&self) -> &[u8] {
        (self.0).to_bytes_be()
    }

    fn from_bytes_le(bytes: &[u8]) -> Option<Self> {
        u16::from_bytes_le(bytes)?.try_into().ok()
    }

    fn from_bytes_be(bytes: &[u8]) -> Option<Self> {
        u16::from_bytes_be(bytes)?.try_into().ok()
    }
}
