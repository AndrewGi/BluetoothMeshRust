use crate::mesh::ModelID;
use alloc::vec::Vec;

// LITTLE ENDIAN
pub struct CompanyID(u16);
impl CompanyID {
    pub const fn byte_len() -> usize {
        2
    }
}
pub struct ProductID(u16);
impl ProductID {
    pub const fn byte_len() -> usize {
        2
    }
}
pub struct VersionID(u16);
impl VersionID {
    pub const fn byte_len() -> usize {
        2
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
pub struct Features(u16);
impl Features {
    pub const fn byte_len() -> usize {
        2
    }
}
const LOCATION_LEN: usize = 2;
pub enum Location {}
pub struct SigModelID {}
impl SigModelID {
    pub const fn byte_len() -> usize {
        2
    }
}
pub struct VendorModelID {}
impl VendorModelID {
    pub const fn byte_len() -> usize {
        CompanyID::byte_len() + 2
    }
}
pub struct Element {
    location: Location,
    sig_models: Vec<SigModelID>,
    vendor_models: Vec<ModelID>,
}
impl Element {
    pub fn byte_len(&self) -> usize {
        LOCATION_LEN
            + 1 // NumS
            + 1 // NumV
            + self.sig_models.len() * SigModelID::byte_len()
            + self.vendor_models.len() * VendorModelID::byte_len()
    }
}
pub struct Elements(Vec<Element>);
impl Elements {
    #[must_use]
    pub fn byte_len(&self) -> usize {
        self.0.iter().map(Element::byte_len).sum()
    }
}
pub struct CompositionDataPage0 {
    cid: CompanyID,
    pid: ProductID,
    vid: VersionID,
    features: Features,
    elements: Elements,
}
impl CompositionDataPage0 {
    pub fn byte_len(&self) -> usize {
        CompanyID::byte_len()
            + ProductID::byte_len()
            + VersionID::byte_len()
            + Features::byte_len()
            + Features::byte_len()
            + self.elements.byte_len()
    }
}
