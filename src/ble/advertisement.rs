use crate::ble::advertisement::AdStructure::Unknown;
use crate::ble::RSSI;
use core::convert::TryFrom;
use core::mem;

#[derive(Ord, PartialOrd, Eq, PartialEq, Copy, Clone, Hash, Debug)]
pub struct AdStructureError(());

#[derive(Ord, PartialOrd, Eq, PartialEq, Copy, Clone, Hash, Debug)]
#[repr(u8)]
pub enum AdType {
    Flags = 0x01,
    IncompleteList16bitUUID = 0x02,
    CompleteList16bitUUID = 0x03,
    IncompleteList32bitUUID = 0x04,
    CompleteList32bitUUID = 0x05,
    IncompleteList128bitUUID = 0x06,
    CompleteList128bitUUID = 0x07,
    ShortenLocalName = 0x08,
    CompleteLocalName = 0x09,
    TxPowerLevel = 0x0A,
    ClassOfDevice = 0x0D,
    SimplePairingHashC = 0x0E,
    SimplePairingRandomizerR = 0x0F,
    SecurityManagerTKValue = 0x10,
    SecurityManagerOOBFlags = 0x11,
    SlaveConnectionIntervalRange = 0x12,
    List16bitSolicitationUUID = 0x14,
    List128bitSolicitationUUID = 0x15,
    ServiceData = 0x16,
    PublicTargetAddress = 0x17,
    RandomTargetAddress = 0x18,
    Appearance = 0x19,
    AdvertisingInterval = 0x1A,
    LEDeviceAddress = 0x1B,
    LERole = 0x1C,
    SimplePairingHashC256 = 0x1D,
    SimplePairingHashRandomizerR256 = 0x1E,
    List32bitSolicitationUUID = 0x1F,
    ServiceData32bitUUID = 0x20,
    ServiceData128bitUUID = 0x21,
    LESecureConfirmValue = 0x22,
    LEConfirmRandomValue = 0x23,
    URI = 0x24,
    IndoorPositioning = 0x25,
    TransportDiscoveryData = 0x26,
    LESupportedFeatures = 0x27,
    ChannelMapUpdateIndication = 0x28,
    PbAdv = 0x29,
    MeshPDU = 0x2A,
    MeshBeacon = 0x2B,
    BIGInfo = 0x2C,
    BroadcastCode = 0x2D,
    Information3DData = 0x3D,
    ManufacturerData = 0xFF,
}
impl From<AdType> for u8 {
    fn from(a: AdType) -> Self {
        a as u8
    }
}
impl TryFrom<u8> for AdType {
    type Error = AdStructureError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0x01 => Ok(AdType::Flags),
            0x02 => Ok(AdType::IncompleteList16bitUUID),
            0x03 => Ok(AdType::CompleteList16bitUUID),
            0x04 => Ok(AdType::IncompleteList32bitUUID),
            0x05 => Ok(AdType::CompleteList32bitUUID),
            0x06 => Ok(AdType::IncompleteList128bitUUID),
            0x07 => Ok(AdType::CompleteList128bitUUID),
            0x08 => Ok(AdType::ShortenLocalName),
            0x09 => Ok(AdType::CompleteLocalName),
            0x0A => Ok(AdType::TxPowerLevel),
            0x0D => Ok(AdType::ClassOfDevice),
            0x0E => Ok(AdType::SimplePairingHashC),
            0x0F => Ok(AdType::SimplePairingRandomizerR),
            0x10 => Ok(AdType::SecurityManagerTKValue),
            0x11 => Ok(AdType::SecurityManagerOOBFlags),
            0x12 => Ok(AdType::SlaveConnectionIntervalRange),
            0x14 => Ok(AdType::List16bitSolicitationUUID),
            0x15 => Ok(AdType::List128bitSolicitationUUID),
            0x16 => Ok(AdType::ServiceData),
            0x17 => Ok(AdType::PublicTargetAddress),
            0x18 => Ok(AdType::RandomTargetAddress),
            0x19 => Ok(AdType::Appearance),
            0x1A => Ok(AdType::AdvertisingInterval),
            0x1B => Ok(AdType::LEDeviceAddress),
            0x1C => Ok(AdType::LERole),
            0x1D => Ok(AdType::SimplePairingHashC256),
            0x1E => Ok(AdType::SimplePairingHashRandomizerR256),
            0x1F => Ok(AdType::List32bitSolicitationUUID),
            0x20 => Ok(AdType::ServiceData32bitUUID),
            0x21 => Ok(AdType::ServiceData128bitUUID),
            0x22 => Ok(AdType::LESecureConfirmValue),
            0x23 => Ok(AdType::LEConfirmRandomValue),
            0x24 => Ok(AdType::URI),
            0x25 => Ok(AdType::IndoorPositioning),
            0x26 => Ok(AdType::TransportDiscoveryData),
            0x27 => Ok(AdType::LESupportedFeatures),
            0x28 => Ok(AdType::ChannelMapUpdateIndication),
            0x29 => Ok(AdType::PbAdv),
            0x2A => Ok(AdType::MeshPDU),
            0x2B => Ok(AdType::MeshBeacon),
            0x2C => Ok(AdType::BIGInfo),
            0x2D => Ok(AdType::BroadcastCode),
            0x3D => Ok(AdType::Information3DData),
            0xFF => Ok(AdType::ManufacturerData),
            _ => Err(AdStructureError(())),
        }
    }
}
pub enum AdStructure {
    MeshPDU(AdStructureDataBuffer),
    MeshBeacon(AdStructureDataBuffer),
    MeshProvision(AdStructureDataBuffer),
    Unknown(AdType, AdStructureDataBuffer),
}
impl AdStructure {
    /// # Panics
    /// Panics if `data` won'f fit in `AdStructureDataBuffer` (look at `AdStructureDataBuffer::new`).
    pub fn new(ad_type: AdType, data: &[u8]) -> AdStructure {
        match ad_type {
            _ => Unknown(ad_type, AdStructureDataBuffer::new(data)),
        }
    }
    pub fn data(&self) -> &[u8] {
        match self {
            AdStructure::MeshPDU(p) => p.as_ref(),
            AdStructure::MeshBeacon(b) => b.as_ref(),
            AdStructure::MeshProvision(p) => p.as_ref(),
            Unknown(_, b) => b.as_ref(),
        }
    }
    pub fn ad_type(&self) -> AdType {
        match self {
            AdStructure::MeshPDU(_) => AdType::MeshPDU,
            AdStructure::MeshBeacon(_) => AdType::MeshBeacon,
            AdStructure::MeshProvision(_) => AdType::PbAdv,
            Unknown(t, _) => *t,
        }
    }
    pub fn len(&self) -> usize {
        // +2 for the ad_type and len u8's
        match self {
            AdStructure::MeshPDU(b) => b.len() + 2,
            AdStructure::MeshBeacon(b) => b.len() + 2,
            AdStructure::MeshProvision(b) => b.len() + 2,
            Unknown(_, b) => b.len() + 2,
        }
    }
}
impl From<&AdStructure> for RawAdvertisement {
    fn from(s: &AdStructure) -> Self {
        let mut out = RawAdvertisement::default();
        out.insert(s);
        out
    }
}
const MAX_AD_LEN: usize = 30;
#[derive(Ord, PartialOrd, Eq, PartialEq, Copy, Clone, Debug, Hash, Default)]
pub struct AdStructureDataBuffer {
    data: [u8; MAX_AD_LEN],
    len: usize,
}
impl AdStructureDataBuffer {
    /// # Panics
    /// Panics if `data.len() > MAX_AD_LEN` (if data won't fit in the buffer).
    pub fn new(data: &[u8]) -> AdStructureDataBuffer {
        assert!(data.len() < MAX_AD_LEN);
        let mut out = AdStructureDataBuffer::default();
        out.data[..data.len()].copy_from_slice(data);
        out.len = data.len();
        out
    }
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }
    pub fn len(&self) -> usize {
        self.len
    }
}
pub struct RawAdStructureBuffer {
    ad_type: AdType,
    data: [u8; MAX_AD_LEN],
    len: usize,
}
impl AsRef<[u8]> for AdStructureDataBuffer {
    fn as_ref(&self) -> &[u8] {
        &self.data[..self.len]
    }
}
impl RawAdStructureBuffer {
    pub fn data(&self) -> &[u8] {
        &self.data[..self.len]
    }
}
const MAX_ADV_LEN: usize = 31;
#[derive(Ord, PartialOrd, Eq, PartialEq, Copy, Clone, Default, Hash, Debug)]
pub struct RawAdvertisement {
    buf: [u8; MAX_ADV_LEN],
    len: usize,
    rssi: Option<RSSI>,
}
impl RawAdvertisement {
    /// Inserts a `AdStructure` into a `RawAdvertisement`
    /// # Panics
    /// Panics if there isn't enough room for the `ad_struct`
    pub fn insert(&mut self, ad_struct: &AdStructure) {
        assert!(
            self.space_left() >= ad_struct.len(),
            "no room for ad_struct"
        );
        self.insert_u8(ad_struct.ad_type().into());
        let len = ad_struct.len();
        self.insert_u8(u8::try_from(len).expect("AdStructures are always < MAX_ADV_LEN"));
        self.buf[self.len..self.len + len].copy_from_slice(ad_struct.data());
        self.len += len;
    }
    fn insert_u8(&mut self, v: u8) {
        assert!(self.len < MAX_ADV_LEN);
        self.buf[self.len] = v;
        self.len += 1;
    }
    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }
    pub const fn len(&self) -> usize {
        self.len
    }
    pub fn space_left(&self) -> usize {
        MAX_ADV_LEN - self.len
    }
    pub fn iter(&self) -> AdStructureIterator<'_> {
        AdStructureIterator {
            data: self.as_ref(),
        }
    }
    pub fn rssi(&self) -> Option<RSSI> {
        self.rssi
    }
}
impl AsRef<[u8]> for RawAdvertisement {
    fn as_ref(&self) -> &[u8] {
        &self.buf[..self.len]
    }
}
pub struct IncomingAdvertisement {
    adv: RawAdvertisement,
    rssi: Option<RSSI>,
}
impl IncomingAdvertisement {
    pub fn adv(&self) -> &RawAdvertisement {
        &self.adv
    }
    pub fn rssi(&self) -> Option<RSSI> {
        self.rssi
    }
}
pub struct OutgoingAdvertisement {}
pub struct AdvertisementData {}
pub struct AdStructureIterator<'a> {
    data: &'a [u8],
}

impl<'a> Iterator for AdStructureIterator<'a> {
    type Item = AdStructure;

    fn next(&mut self) -> Option<Self::Item> {
        if self.data.len() < 2 {
            return None;
        }
        let d = mem::replace(&mut self.data, &mut []);
        let len = usize::from(d[0]);
        let (data, rest) = d.split_at(len + 1);
        self.data = rest;
        let ad_type = AdType::try_from(data[1]).ok()?;
        // Drop the len and ad_type from the front of the ad structure.
        let data = &data[2..];
        Some(AdStructure::new(ad_type, data))
    }
}
#[cfg(test)]
mod tests {
    use crate::ble::advertisement::AdType;
    use core::convert::TryFrom;

    #[test]
    fn test_ad_type_try_into() {
        for i in 0u8..=255u8 {
            match AdType::try_from(i) {
                Ok(t) => assert_eq!(u8::from(t), i),
                Err(_) => (),
            }
        }
    }
}
