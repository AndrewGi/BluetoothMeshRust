//use crate::access::ModelIdentifier;
use crate::access::{ModelIdentifier, SigModelID, VendorModelID};
use crate::address::{Address, UnicastAddress};
use crate::foundation::model::ModelComposition;
use crate::foundation::FoundationStateError;
use crate::mesh::{AppKeyIndex, CompanyID, ModelID, TTL};
use crate::serializable::bytes::ToFromBytesEndian;
use alloc::collections::BTreeMap;
use alloc::vec::Vec;
use core::convert::TryInto;

//use alloc::collections::BTreeMap;
const MAX_MODELS: usize = 255;
#[derive(Clone, Ord, PartialOrd, PartialEq, Debug, Hash, Eq)]
pub struct Element {
    location: Location,
    address: UnicastAddress,
    sig_models: Vec<ModelComposition>,
    vendor_models: Vec<ModelComposition>,
}
impl Element {
    pub fn new_empty(location: Location, element_address: UnicastAddress) -> Self {
        Self {
            address: element_address,
            location,
            sig_models: Vec::new(),
            vendor_models: Vec::new(),
        }
    }
    pub fn num_s(&self) -> u8 {
        self.sig_models
            .len()
            .try_into()
            .expect("elements only support up to 255 SIG models")
    }
    pub fn num_v(&self) -> u8 {
        self.vendor_models
            .len()
            .try_into()
            .expect("elements only support up to 255 vendor models")
    }
    pub fn byte_len(&self) -> usize {
        Location::byte_len()
            + 1
            + 1
            + self.sig_models.len() * SigModelID::byte_len()
            + self.vendor_models.len() * VendorModelID::byte_len()
    }
    pub const fn min_byte_len() -> usize {
        Location::byte_len() + 1 + 1
    }
    pub fn try_unpack_from(buf: &[u8]) -> Option<Self> {
        if buf.len() < Self::min_byte_len() {
            None
        } else {
            let loc = Location::from_bytes_le(&buf[..2])?;
            let num_s = buf[2];
            let num_v = buf[3];
            if buf.len()
                < Self::min_byte_len()
                    + usize::from(num_s) * ModelIdentifier::sig_byte_len()
                    + usize::from(num_v) * ModelIdentifier::vendor_byte_len()
            {
                None
            } else {
                let mut sig_models = Vec::new();
                for i in 0..usize::from(num_s) {
                    sig_models.push(ModelIdentifier::from)
                }
                //let mut vendor_models = Vec::new();
                unimplemented!()
            }
        }
    }
    pub fn pack_into(&self, buf: &mut [u8]) {
        assert!(buf.len() >= self.byte_len());
        let buf = &mut buf[..self.byte_len()];
        buf[0..2].copy_from_slice(&self.location.to_bytes_le());
        buf[2] = self.num_s();
        buf[3] = self.num_v();
        let mut position = 0usize;
        for model in self.sig_models.iter() {
            // This could be change to a debug_assert.
            assert!(model.is_sig(), "non SIG model in sig_models");
            buf[position..position + ModelID::byte_size()]
                .copy_from_slice(&model.model_identifier.model_id().to_bytes_le());
            position += ModelID::byte_size();
        }
        for model in self.vendor_models.iter() {
            assert!(model.is_vendor(), "SIG model in vendor_models");
            model
                .model_identifier
                .pack_into(&mut buf[position..position + ModelIdentifier::vendor_byte_len()]);
            position += ModelIdentifier::vendor_byte_len();
        }
        debug_assert!(position == buf.len());
    }
    /// # Panics
    /// Panics if a model with the same `ModelIdentifier` exists.
    /// Or if there are already 255 vendor or sig models.
    pub fn add_model(&mut self, model: ModelComposition) {
        if model.is_sig() {
            assert!(
                self.sig_models.len() < MAX_MODELS,
                "too many SIG models exist"
            );
            self.sig_models.push(model)
        }
    }
}

const LOCATION_LEN: usize = 2;
/// Bluetooth GATT Namespace Descriptions. Used to describe the physical location an Element.
/// Examples such as First (`Location::Numbered(1)`), Unknown(`Location::Numbered(0)`),
/// Inside(`Location::Inside`), etc. [See GATT Namespace Descriptors for more](https://www.bluetooth.com/specifications/assigned-numbers/gatt-namespace-descriptors/)
#[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Debug, Hash)]
pub enum Location {
    Numbered(u8), // Contains 0x00--0xFF.
    Invalid(u16), // Contains any unrecognized Location Descriptors
    Front,
    Back,
    Top,
    Bottom,
    Upper,
    Lower,
    Main,
    Backup,
    Auxiliary,
    Supplementary,
    Flash,
    Inside,
    Outside,
    Left,
    Right,
    Internal,
    External,
}
impl Location {
    pub fn new(location: u16) -> Self {
        location.into()
    }
    pub const fn byte_len() -> usize {
        LOCATION_LEN
    }
}
impl From<Location> for u16 {
    fn from(location: Location) -> Self {
        match location {
            Location::Numbered(n) => n.into(),
            Location::Invalid(n) => n,
            Location::Front => 0x0100,
            Location::Back => 0x0101,
            Location::Top => 0x0102,
            Location::Bottom => 0x0103,
            Location::Upper => 0x0104,
            Location::Lower => 0x0105,
            Location::Main => 0x0106,
            Location::Backup => 0x0107,
            Location::Auxiliary => 0x0108,
            Location::Supplementary => 0x0109,
            Location::Flash => 0x010A,
            Location::Inside => 0x010B,
            Location::Outside => 0x010C,
            Location::Left => 0x010D,
            Location::Right => 0x010E,
            Location::Internal => 0x010F,
            Location::External => 0x0110,
        }
    }
}
impl From<u16> for Location {
    fn from(v: u16) -> Self {
        match v {
            0x00..=0xFF => {
                Location::Numbered(v.try_into().expect("numbered descriptors are 0--255"))
            }
            0x0100 => Location::Front,
            0x0101 => Location::Back,
            0x0102 => Location::Top,
            0x0103 => Location::Bottom,
            0x0104 => Location::Upper,
            0x0105 => Location::Lower,
            0x0106 => Location::Main,
            0x0107 => Location::Backup,
            0x0108 => Location::Auxiliary,
            0x0109 => Location::Supplementary,
            0x010A => Location::Flash,
            0x010B => Location::Inside,
            0x010C => Location::Outside,
            0x010D => Location::Left,
            0x010E => Location::Right,
            0x010F => Location::Internal,
            0x0110 => Location::External,
            _ => Location::Invalid(v),
        }
    }
}
impl ToFromBytesEndian for Location {
    type AsBytesType = [u8; 2];

    #[must_use]
    fn to_bytes_le(&self) -> Self::AsBytesType {
        u16::from(*self).to_bytes_le()
    }

    #[must_use]
    fn to_bytes_be(&self) -> Self::AsBytesType {
        u16::from(*self).to_bytes_be()
    }

    #[must_use]
    fn from_bytes_le(bytes: &[u8]) -> Option<Self> {
        Some(Location::new(u16::from_bytes_le(bytes)?))
    }

    #[must_use]
    fn from_bytes_be(bytes: &[u8]) -> Option<Self> {
        Some(Location::new(u16::from_bytes_be(bytes)?))
    }
}

#[derive(Clone, Ord, PartialOrd, PartialEq, Debug, Hash, Eq)]
pub struct Elements(Vec<Element>);
impl Elements {
    #[must_use]
    pub fn byte_len(&self) -> usize {
        self.0.iter().map(Element::byte_len).sum()
    }
    /// # Panics
    /// Panics if `buf.len() < self.byte_len()`.
    pub fn pack_into(&self, buf: &mut [u8]) {
        assert!(buf.len() >= self.byte_len());
        let buf = &mut buf[..self.byte_len()];
        let mut position = 0usize;
        for element in self.0.iter() {
            element.pack_into(&mut buf[position..position + element.byte_len()]);
            position += element.byte_len();
        }
        debug_assert_eq!(position, buf.len(), "elements did not fill the buffer");
    }
    pub fn try_unpack_from(mut buf: &[u8]) -> Option<Self> {
        let mut out = Vec::new();
        while !buf.is_empty() {
            let element = Element::try_unpack_from(buf)?;
            let (_, rest) = buf.split_at(element.byte_len());
            buf = rest;
            out.push(element);
        }
        Some(Elements(out))
    }
}
