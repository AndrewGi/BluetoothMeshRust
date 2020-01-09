use core::convert::TryFrom;

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
pub enum AdStructure {}
pub struct RawAdStructure<'a> {
    ad_type: AdType,
    data: &'a [u8],
}
const MAX_AD_LEN: usize = 30;
impl<'a> RawAdStructure<'a> {
    /// # Panics
    /// Panics if `data.len() > MAX_AD_LEN`
    pub fn new(ad_type: AdType, data: &'a [u8]) -> RawAdStructure<'a> {
        assert!(
            data.len() <= MAX_AD_LEN,
            "data too big to fit in a advertisement PDU"
        );
        Self { ad_type, data }
    }
}
pub struct RawAdStructureBuffer {
    ad_type: AdType,
    data: [u8; MAX_AD_LEN],
    len: usize,
}
impl RawAdStructureBuffer {
    pub fn data(&self) -> &[u8] {
        &self.data[..self.len]
    }
}
impl<'a> From<&'a RawAdStructureBuffer> for RawAdStructure<'a> {
    fn from(b: &'a RawAdStructureBuffer) -> Self {
        Self::new(b.ad_type, &b.data[..b.len])
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
