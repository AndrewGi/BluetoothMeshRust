//! Bluetooth Mesh Beacon Layer. Currently only supports `SecureNetworkBeacon`s and
//! `UnprovisionedDeviceBeacon`s.
use crate::uuid::UUID;

#[repr(u16)]
pub enum OOBFlags {
    Other = 0x00,
    ElectronicURI = 0x01,
    MachineReadable2DCode = 0x02,
    BarCode = 0x03,
    NearFieldCommunications = 0x04,
    Number = 0x05,
    String = 0x06,
    RFU0 = 0x07,
    RFU1 = 0x08,
    RFU2 = 0x09,
    RFU3 = 0x0A,
    OnBox = 0x0B,
    InsideBox = 0x0C,
    OnPieceOfPaper = 0x0D,
    InsideManual = 0x0E,
    OnDevice = 0x0F,
}
impl From<OOBFlags> for u16 {
    fn from(f: OOBFlags) -> Self {
        f as u16
    }
}

#[derive(Copy, Clone, PartialOrd, PartialEq, Ord, Eq, Hash, Default, Debug)]
pub struct OOBInformation(pub u16);
impl OOBInformation {
    pub fn set(&mut self, flag: OOBFlags) {
        self.0 |= 1u16 << u16::from(flag);
    }
    pub fn get(&self, flag: OOBFlags) -> bool {
        self.0 & (1u16 << u16::from(flag)) != 0
    }
}
#[derive(Copy, Clone, PartialOrd, PartialEq, Ord, Eq, Debug, Hash)]
pub struct URIHash(pub u32);
#[derive(Copy, Clone, PartialOrd, PartialEq, Ord, Eq, Debug, Hash)]
pub struct UnprovisionedDeviceBeacon {
    pub uuid: UUID,
    pub oob_information: OOBInformation,
    pub uri_hash: Option<URIHash>,
}
pub struct SecureNetworkBeacon {}
pub enum BeaconType {
    Unprovisioned = 0x00,
    SecureNetwork = 0x01,
}
pub enum Beacon {
    Unprovisioned(UnprovisionedDeviceBeacon),
    SecureNetwork(SecureNetworkBeacon),
}
pub struct PackedBeacon {}
impl AsRef<[u8]> for PackedBeacon {
    fn as_ref(&self) -> &[u8] {
        unimplemented!()
    }
}
