//! Foundation Layer. Handles Publication, Config, etc.
use crate::access::{SigModelID, VendorModelID};
use crate::foundation::element::Elements;
use crate::mesh::{CompanyID, ModelID};
use crate::serializable::bytes::ToFromBytesEndian;
use crate::upper::AppPayload;
use alloc::boxed::Box;
use alloc::vec::Vec;

pub mod element;
pub mod health;
pub mod model;
pub mod publication;
pub mod state;
// LITTLE ENDIAN

#[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Debug, Hash)]
pub enum StatusCode {}

#[derive(Ord, PartialOrd, Eq, PartialEq, Copy, Clone, Hash, Debug)]
pub struct FoundationStateError(());

#[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Debug, Hash)]
pub struct ProductID(pub u16);
impl ProductID {
    pub const fn byte_len() -> usize {
        2
    }
}

impl ToFromBytesEndian for ProductID {
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
        Some(ProductID(u16::from_bytes_le(bytes)?))
    }

    #[must_use]
    fn from_bytes_be(bytes: &[u8]) -> Option<Self> {
        Some(ProductID(u16::from_bytes_be(bytes)?))
    }
}

#[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Debug, Hash)]
pub struct VersionID(pub u16);
impl VersionID {
    pub const fn byte_len() -> usize {
        2
    }
}
impl ToFromBytesEndian for VersionID {
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
        Some(VersionID(u16::from_bytes_le(bytes)?))
    }

    #[must_use]
    fn from_bytes_be(bytes: &[u8]) -> Option<Self> {
        Some(VersionID(u16::from_bytes_be(bytes)?))
    }
}

/// Minimum number of replay protection list entries
pub struct Crpl(u16);
impl Crpl {
    pub const fn byte_len() -> usize {
        2
    }
}
pub enum FeatureFlags {
    Relay = 0b0001,
    Proxy = 0b0010,
    Friend = 0b0100,
    LowPower = 0b1000,
}
impl From<FeatureFlags> for u16 {
    fn from(f: FeatureFlags) -> Self {
        f as u16
    }
}
impl ToFromBytesEndian for Features {
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
        Some(Features(u16::from_bytes_le(bytes)?))
    }

    #[must_use]
    fn from_bytes_be(bytes: &[u8]) -> Option<Self> {
        Some(Features(u16::from_bytes_be(bytes)?))
    }
}
#[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Debug, Hash)]
pub struct Features(u16);
impl Features {
    pub const fn byte_len() -> usize {
        2
    }
    pub fn set(&mut self, feature: FeatureFlags) {
        self.0 |= u16::from(feature)
    }
    pub fn clear(&mut self, feature: FeatureFlags) {
        self.0 |= !u16::from(feature)
    }
    #[must_use]
    pub fn get(&self, feature: FeatureFlags) -> bool {
        self.0 & u16::from(feature) != 0
    }
}
#[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Debug, Hash)]
pub struct CRPL(pub u16);
impl CRPL {
    pub const fn byte_len() -> usize {
        2
    }
}
impl ToFromBytesEndian for CRPL {
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
        Some(CRPL(u16::from_bytes_le(bytes)?))
    }

    #[must_use]
    fn from_bytes_be(bytes: &[u8]) -> Option<Self> {
        Some(CRPL(u16::from_bytes_be(bytes)?))
    }
}
#[derive(Clone, Ord, PartialOrd, PartialEq, Debug, Hash, Eq)]
pub struct CompositionDataPage0 {
    cid: CompanyID,
    pid: ProductID,
    vid: VersionID,
    crpl: CRPL,
    features: Features,
    elements: Elements,
}
impl CompositionDataPage0 {
    pub fn byte_len(&self) -> usize {
        CompanyID::byte_len()
            + ProductID::byte_len()
            + VersionID::byte_len()
            + CRPL::byte_len()
            + Features::byte_len()
            + self.elements.byte_len()
    }
    pub const fn min_byte_len() -> usize {
        CompanyID::byte_len()
            + ProductID::byte_len()
            + VersionID::byte_len()
            + CRPL::byte_len()
            + Features::byte_len()
    }
    pub fn try_unpack_from(&self, data: &[u8]) {
        unimplemented!()
    }
    pub fn pack_into(&self, buf: &mut [u8]) {
        assert!(buf.len() >= self.byte_len());
        let buf = &mut buf[..self.byte_len()];
        buf[0..2].copy_from_slice(&self.cid.to_bytes_le());
        buf[2..4].copy_from_slice(&self.pid.to_bytes_le());
        buf[4..6].copy_from_slice(&self.vid.to_bytes_le());
        buf[6..8].copy_from_slice(&self.crpl.to_bytes_le());
        buf[8..10].copy_from_slice(&self.features.to_bytes_le());
        self.elements.pack_into(&mut buf[10..]);
    }
    pub fn as_app_payload(&self) -> AppPayload<Box<[u8]>> {
        let mut buf = Vec::with_capacity(self.byte_len()).into_boxed_slice();
        self.pack_into(buf.as_mut());
        AppPayload::new(buf)
    }
}
