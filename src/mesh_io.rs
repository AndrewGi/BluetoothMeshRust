use crate::net::PDU;
use crate::properties::characteristics::Characteristics::DescriptorValueChanged;
use core::time::Duration;

#[derive(Copy, Clone, Hash, Ord, PartialOrd, Eq, PartialEq, Debug)]
pub enum PDUType {
    Network,
    Beacon,
    Provision,
    URI,
    Other(u8),
}
impl PDUType {
    pub fn advertisement_type(self) -> u8 {
        match self {
            PDUType::Network => 0x2A,
            PDUType::Beacon => 0x2B,
            PDUType::Provision => 0x29,
            PDUType::URI => 0x24,
            PDUType::Other(o) => o,
        }
    }
    pub fn from_advertisement_type(v: u8) -> PDUType {
        match v {
            0x2A => PDUType::Network,
            0x2B => PDUType::Beacon,
            0x29 => PDUType::Provision,
            0x24 => PDUType::URI,
            _ => PDUType::Other(v),
        }
    }
    pub fn is_other(&self) -> bool {
        match self {
            PDUType::Other(_) => true,
            _ => false,
        }
    }
    pub fn is_mesh(&self) -> bool {
        !self.is_other()
    }
}
impl From<PDUType> for u8 {
    fn from(p: PDUType) -> Self {
        p.advertisement_type()
    }
}
impl From<u8> for PDUType {
    fn from(v: u8) -> Self {
        PDUType::from_advertisement_type(v)
    }
}
const BLE_ADV_MAX_LEN: usize = 31;
#[derive(Copy, Clone, Hash, Debug, Default)]
pub struct RawMeshPDU {
    buffer: [u8; BLE_ADV_MAX_LEN],
    length: u8,
}
impl RawMeshPDU {
    pub fn new_with_length(length: usize) -> RawMeshPDU {
        assert!(
            length <= BLE_ADV_MAX_LEN,
            "bytes won't fit in one adv packet"
        );
        RawMeshPDU {
            buffer: Default::default(),
            length: length as u8,
        }
    }
    pub fn new(bytes: &[u8]) -> RawMeshPDU {
        let mut out = Self::new_with_length(bytes.len());
        out.data_mut().copy_from_slice(bytes);
        out
    }
    pub fn new_payload(pdu_type: PDUType, payload: &[u8]) -> RawMeshPDU {
        let mut out = Self::new_with_length(payload.len() + 1);
        out.buffer[0] = pdu_type.into();
        out.data_mut()[1..].copy_from_slice(payload);
        out
    }
    pub fn pdu_type(&self) -> PDUType {
        self.buffer[0].into()
    }
    pub fn len(&self) -> usize {
        self.length as usize
    }
    pub fn data(&self) -> &[u8] {
        &self.buffer[..self.length as usize]
    }
    pub fn data_mut(&mut self) -> &mut [u8] {
        &mut self.buffer[..self.length as usize]
    }
}
impl AsRef<[u8]> for RawMeshPDU {
    fn as_ref(&self) -> &[u8] {
        self.data()
    }
}
impl AsMut<[u8]> for RawMeshPDU {
    fn as_mut(&mut self) -> &mut [u8] {
        self.data_mut()
    }
}
pub struct IOTransmitParameters {}
pub struct MeshIOPDU {
    transmit_parameters: IOTransmitParameters,
    pdu: RawMeshPDU,
}
pub struct MeshPDUQueue {
    queue: crate::scheduler::TimeQueue<MeshIOPDU>,
}
impl MeshPDUQueue {
    pub fn add(delay: Duration, io_pdu: MeshIOPDU) {}
}
