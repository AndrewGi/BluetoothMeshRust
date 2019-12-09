use crate::uuid::UUID;
use core::convert::TryInto;

#[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq)]
pub struct UnicastAddress(u16);
#[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq)]
pub struct GroupAddress(u16);
#[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq)]
pub struct VirtualAddressHash(u16);
#[derive(Copy, Clone)]
pub struct VirtualAddress(VirtualAddressHash, UUID);

impl TryInto<UnicastAddress> for u16 {
    type Error = ();

    fn try_into(self) -> Result<UnicastAddress, Self::Error> {
        if self == 0 {
            Err(())
        } else if self & 0x8000 == 0 {
            Ok(UnicastAddress(self))
        } else {
            Err(())
        }
    }
}

impl TryInto<GroupAddress> for u16 {
    type Error = ();

    fn try_into(self) -> Result<GroupAddress, Self::Error> {
        if self & 0xC000 == 0xC000 {
            Ok(GroupAddress(self))
        } else {
            Err(())
        }
    }
}

impl TryInto<VirtualAddressHash> for u16 {
    type Error = ();
    fn try_into(self) -> Result<VirtualAddressHash, Self::Error> {
        if self & 0xC000 == 0x8000 {
            Ok(VirtualAddressHash(self))
        } else {
            Err(())
        }
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
    fn is_assigned(self) -> bool {
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

impl Into<u16> for Address {
    fn into(self) -> u16 {
        match self {
            Address::Unassigned => 0u16,
            Address::Unicast(u) => u.0,
            Address::Group(g) => g.0,
            Address::Virtual(v) => (v.0).0,
            Address::VirtualHash(v) => v.0,
        }
    }
}
impl Into<Address> for u16 {
    fn into(self) -> Address {
        if self == 0 {
            Address::Unassigned
        } else if self & 0x8000 == 0 {
            Address::Unicast(UnicastAddress(self))
        } else if self & 0xC000 == 0xC000 {
            Address::Group(GroupAddress(self))
        } else {
            Address::VirtualHash(VirtualAddressHash(self))
        }
    }
}
