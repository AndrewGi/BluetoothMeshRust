//! Bluetooth Mesh Addresses.
//! All address are 16-bit except for Virtual Addresses. Virtual Address are 128-bit UUIDs but only
//! a 16-bit hash of the UUID is sent with message.
//!
//! | Bits (16)             | Type          |
//! | --------------------- | ------------- |
//! | 0b0000 0000 0000 0000 | Unassigned    |
//! | 0b0xxx xxxx xxxx xxxx | Unicast       |
//! | 0b10xx xxxx xxxx xxxx | Virtual       |
//! | 0b11xx xxxx xxxx xxxx | Group         |
//!
//! Endian depends on layer!!
//! Little: Access/Foundation
//! Big: Everything else
use crate::bytes::ToFromBytesEndian;
use crate::crypto::aes::AESCipher;
use crate::crypto::k_funcs::VTAD;
use crate::uuid::UUID;
use core::convert::{TryFrom, TryInto};

pub const ADDRESS_LEN: usize = 2;

const UNICAST_BIT: u16 = 0x8000;
const UNICAST_MASK: u16 = !UNICAST_BIT;

const GROUP_BIT: u16 = 0xC000;
const GROUP_MASK: u16 = !GROUP_BIT;

const VIRTUAL_BIT: u16 = 0x8000;
const VIRTUAL_MASK: u16 = GROUP_MASK;

/// Element Unicast Address. Each Element has one Unicast assigned to it.
#[cfg_attr(feature = "serde-1", derive(serde::Serialize, serde::Deserialize))]
#[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug)]
pub struct UnicastAddress(u16);
/// Group Address. Some Group Address are reserved.
///
/// | Values        | Group Name    |
/// | ------------- | ------------- |
/// | 0xFF00-0xFFFB | RFU           |
/// | 0xFFFC        | All Proxies   |
/// | 0xFFFD        | All Friends   |
/// | 0xFFFE        | All Relays    |
/// | 0xFFFF        | All Nodes     |
#[cfg_attr(feature = "serde-1", derive(serde::Serialize, serde::Deserialize))]
#[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug)]
pub struct GroupAddress(u16);
impl GroupAddress {
    /// # Panics
    /// Panics if `group_address` isn't a value group address.
    pub fn new(group_address: u16) -> Self {
        match Self::try_from(group_address) {
            Ok(g) => g,
            Err(_) => panic!("invalid group address given"),
        }
    }
    /// Group address corresponding to all proxies nodes.
    pub const fn all_proxies() -> GroupAddress {
        GroupAddress(0xFFFC)
    }
    /// Group address corresponding to all friends nodes.
    pub const fn all_friends() -> GroupAddress {
        GroupAddress(0xFFFD)
    }
    /// Group address corresponding to all relay nodes.
    pub const fn all_relays() -> GroupAddress {
        GroupAddress(0xFFE)
    }
    /// Group address corresponding to all nodes.
    pub const fn all_nodes() -> GroupAddress {
        GroupAddress(0xFFFF)
    }
}
const VIRTUAL_ADDRESS_HASH_MAX: u16 = (1_u16 << 14) - 1;
/// Only stores the 14 bit hash of the virtual UUID.
/// For the full 128 bit UUID, look at [`VirtualAddress`]
#[cfg_attr(feature = "serde-1", derive(serde::Serialize, serde::Deserialize))]
#[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug)]
pub struct VirtualAddressHash(u16);
impl VirtualAddressHash {
    /// Create a 14 bit `VirtualAddressHash` from the 16 bit input.
    /// # Panics
    /// Panics if `address > VIRTUAL_ADDRESS_HASH_MAX`.
    pub fn new(address: u16) -> VirtualAddressHash {
        assert_eq!(
            address & VIRTUAL_MASK,
            VIRTUAL_BIT,
            "non virtual hash address '{}'",
            address
        );
        VirtualAddressHash(address)
    }
    /// Creates a 14 bit `VirtualAddressHash` by masking a u16 to a u14.
    pub fn new_masked(address: u16) -> VirtualAddressHash {
        VirtualAddressHash((address & VIRTUAL_ADDRESS_HASH_MAX) | VIRTUAL_BIT)
    }
    pub fn just_hash(self) -> u16 {
        self.0 & VIRTUAL_ADDRESS_HASH_MAX
    }
}
/// Stores the 14-bit hash and full 128 bit virtual UUID. Only the 14-bit hash is sent with
/// messages over the air. During the application decryption process, the UUID is supplied to the
/// AES CCM decryptor as associated data. If the hash matches but the decryption fails (MIC doesn't
/// match), the message doesn't belong to that VirtualAddress.
#[cfg_attr(feature = "serde-1", derive(serde::Serialize, serde::Deserialize))]
#[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug)]
pub struct VirtualAddress(VirtualAddressHash, UUID);
impl VirtualAddress {
    /// Creates a Virtual Address by calculate the hash of the UUID (using AES CMAC).
    pub fn hash_uuid(uuid: &UUID) -> VirtualAddressHash {
        let k = AESCipher::from(VTAD).cmac(uuid.as_ref());
        VirtualAddressHash::new_masked(u16::from_be_bytes([k.as_ref()[14], k.as_ref()[15]]))
    }
    pub fn new(uuid: &UUID) -> VirtualAddress {
        VirtualAddress(Self::hash_uuid(uuid), uuid.clone())
    }
    fn new_parts(hash: VirtualAddressHash, uuid: &UUID) -> Self {
        VirtualAddress(hash, *uuid)
    }
    pub fn uuid(&self) -> &UUID {
        &self.1
    }
    pub fn hash(&self) -> VirtualAddressHash {
        self.0
    }
}
impl AsRef<UUID> for VirtualAddress {
    fn as_ref(&self) -> &UUID {
        &self.1
    }
}
impl From<&UUID> for VirtualAddress {
    fn from(uuid: &UUID) -> Self {
        Self::new(uuid)
    }
}
impl UnicastAddress {
    /// Creates a new `UnicastAddress`.
    /// # Panics
    /// Panics if the `u16` is not a valid `UnicastAddress`. (Panics if `u16==0 || u16&UNICAST_BIT!=0`)
    #[must_use]
    pub fn new(v: u16) -> UnicastAddress {
        assert!(
            (v & UNICAST_BIT) == 0 || v == 0,
            "non unicast address '{}'",
            v
        );
        UnicastAddress(v)
    }
    /// Creates a Unicast address by masking any u16 into it.
    /// # Panics
    /// Panics if the `u16` masked equals `0`.
    #[must_use]
    pub fn from_mask_u16(v: u16) -> UnicastAddress {
        assert_ne!(v & UNICAST_MASK, 0, "unassigned unicast address");
        UnicastAddress(v & UNICAST_MASK)
    }
}
#[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Debug, Hash)]
pub struct AddressError(());
impl TryFrom<u16> for UnicastAddress {
    type Error = AddressError;

    fn try_from(v: u16) -> Result<UnicastAddress, Self::Error> {
        if v == 0 {
            Err(AddressError(()))
        } else if v & UNICAST_BIT == 0 {
            Ok(UnicastAddress(v))
        } else {
            Err(AddressError(()))
        }
    }
}

impl TryFrom<u16> for GroupAddress {
    type Error = AddressError;

    fn try_from(v: u16) -> Result<GroupAddress, Self::Error> {
        if v & 0xC000 == 0xC000 {
            Ok(GroupAddress(v))
        } else {
            Err(AddressError(()))
        }
    }
}

impl TryFrom<u16> for VirtualAddressHash {
    type Error = AddressError;
    fn try_from(v: u16) -> Result<VirtualAddressHash, Self::Error> {
        if v & 0xC000 == 0x8000 {
            Ok(VirtualAddressHash(v))
        } else {
            Err(AddressError(()))
        }
    }
}

impl From<UnicastAddress> for u16 {
    #[must_use]
    fn from(v: UnicastAddress) -> Self {
        v.0
    }
}
impl From<GroupAddress> for u16 {
    #[must_use]
    fn from(v: GroupAddress) -> Self {
        v.0
    }
}
impl From<VirtualAddressHash> for u16 {
    #[must_use]
    fn from(v: VirtualAddressHash) -> Self {
        v.0
    }
}
impl From<VirtualAddress> for u16 {
    #[must_use]
    fn from(v: VirtualAddress) -> Self {
        (v.0).0
    }
}
#[cfg_attr(feature = "serde-1", derive(serde::Serialize, serde::Deserialize))]
#[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug)]
pub enum Address {
    Unassigned,
    Unicast(UnicastAddress),
    Group(GroupAddress),
    Virtual(VirtualAddress),
    VirtualHash(VirtualAddressHash),
}

impl Address {
    #[must_use]
    pub fn is_assigned(&self) -> bool {
        match self {
            Address::Unassigned => false,
            _ => true,
        }
    }
    #[must_use]
    pub fn is_unicast(&self) -> bool {
        match self {
            Address::Unicast(_) => true,
            _ => false,
        }
    }

    #[must_use]
    pub fn is_group(&self) -> bool {
        match self {
            Address::Group(_) => true,
            _ => false,
        }
    }

    #[must_use]
    pub fn is_virtual(&self) -> bool {
        match self {
            Address::Virtual(_) => true,
            Address::VirtualHash(_) => true,
            _ => false,
        }
    }

    #[must_use]
    pub fn is_full_virtual(&self) -> bool {
        match self {
            Address::Virtual(_) => true,
            _ => false,
        }
    }
    #[must_use]
    pub fn virtual_hash(&self) -> Option<VirtualAddressHash> {
        match self {
            Address::Virtual(v) => Some(v.0),
            Address::VirtualHash(h) => Some(*h),
            _ => None,
        }
    }
    #[must_use]
    pub fn unicast(&self) -> Option<UnicastAddress> {
        match self {
            Address::Unicast(u) => Some(*u),
            _ => None,
        }
    }
    #[must_use]
    pub fn group(&self) -> Option<GroupAddress> {
        match self {
            Address::Group(g) => Some(*g),
            _ => None,
        }
    }
    #[must_use]
    pub fn value(&self) -> u16 {
        self.into()
    }
}

impl Default for Address {
    #[must_use]
    fn default() -> Self {
        Address::Unassigned
    }
}

impl From<u16> for Address {
    #[must_use]
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
    #[must_use]
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
    type Error = AddressError;

    fn try_from(value: &Address) -> Result<Self, Self::Error> {
        match value {
            Address::Unicast(u) => Ok(*u),
            _ => Err(AddressError(())),
        }
    }
}
impl TryFrom<&Address> for VirtualAddressHash {
    type Error = AddressError;

    fn try_from(value: &Address) -> Result<Self, Self::Error> {
        match value {
            Address::VirtualHash(h) => Ok(*h),
            _ => Err(AddressError(())),
        }
    }
}
impl TryFrom<&Address> for VirtualAddress {
    type Error = AddressError;

    fn try_from(value: &Address) -> Result<Self, Self::Error> {
        match value {
            Address::Virtual(v) => Ok(*v),
            _ => Err(AddressError(())),
        }
    }
}
impl TryFrom<&Address> for GroupAddress {
    type Error = AddressError;

    fn try_from(value: &Address) -> Result<Self, Self::Error> {
        match value {
            Address::Group(g) => Ok(*g),
            _ => Err(AddressError(())),
        }
    }
}
impl ToFromBytesEndian for Address {
    type AsBytesType = [u8; 2];

    #[must_use]
    fn to_bytes_le(&self) -> Self::AsBytesType {
        match self {
            Address::Unassigned => 0_u16.to_bytes_le(),
            Address::Unicast(u) => (u.0).to_bytes_le(),
            Address::Group(g) => (g.0).to_bytes_le(),
            Address::Virtual(v) => ((v.0).0).to_bytes_le(),
            Address::VirtualHash(h) => (h.0).to_bytes_le(),
        }
    }

    #[must_use]
    fn to_bytes_be(&self) -> Self::AsBytesType {
        match self {
            Address::Unassigned => 0_u16.to_bytes_be(),
            Address::Unicast(u) => (u.0).to_bytes_be(),
            Address::Group(g) => (g.0).to_bytes_be(),
            Address::Virtual(v) => ((v.0).0).to_bytes_be(),
            Address::VirtualHash(h) => (h.0).to_bytes_be(),
        }
    }

    #[must_use]
    fn from_bytes_le(bytes: &[u8]) -> Option<Self> {
        Some(u16::from_bytes_le(bytes)?.into())
    }

    #[must_use]
    fn from_bytes_be(bytes: &[u8]) -> Option<Self> {
        Some(u16::from_bytes_be(bytes)?.into())
    }
}

impl ToFromBytesEndian for UnicastAddress {
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
        u16::from_bytes_le(bytes)?.try_into().ok()
    }

    #[must_use]
    fn from_bytes_be(bytes: &[u8]) -> Option<Self> {
        u16::from_bytes_be(bytes)?.try_into().ok()
    }
}

impl ToFromBytesEndian for VirtualAddressHash {
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
        u16::from_bytes_le(bytes)?.try_into().ok()
    }

    #[must_use]
    fn from_bytes_be(bytes: &[u8]) -> Option<Self> {
        u16::from_bytes_be(bytes)?.try_into().ok()
    }
}
impl ToFromBytesEndian for GroupAddress {
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
        u16::from_bytes_le(bytes)?.try_into().ok()
    }

    #[must_use]
    fn from_bytes_be(bytes: &[u8]) -> Option<Self> {
        u16::from_bytes_be(bytes)?.try_into().ok()
    }
}
