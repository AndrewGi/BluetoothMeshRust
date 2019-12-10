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
