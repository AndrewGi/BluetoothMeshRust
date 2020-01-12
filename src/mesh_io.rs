use crate::net::EncryptedPDU;
use crate::scheduler::TimeQueueSlotKey;
//use crate::timestamp::Timestamp;
use crate::ble::advertisement::{AdStructure, AdStructureDataBuffer, RawAdvertisement};
use crate::ble::gap::{Advertiser, Scanner};
use crate::provisioning::pb_adv::PackedPDU;
use crate::timestamp::TimestampTrait;
use crate::{beacon, net, provisioning};
use alloc::boxed::Box;
use core::convert::TryFrom;
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
    #[must_use]
    pub fn advertisement_type(self) -> u8 {
        match self {
            PDUType::Network => 0x2A,
            PDUType::Beacon => 0x2B,
            PDUType::Provision => 0x29,
            PDUType::URI => 0x24,
            PDUType::Other(o) => o,
        }
    }
    #[must_use]
    pub fn from_advertisement_type(v: u8) -> PDUType {
        match v {
            0x2A => PDUType::Network,
            0x2B => PDUType::Beacon,
            0x29 => PDUType::Provision,
            0x24 => PDUType::URI,
            _ => PDUType::Other(v),
        }
    }
    #[must_use]
    pub fn is_other(self) -> bool {
        match self {
            Self::Other(_) => true,
            _ => false,
        }
    }
    #[must_use]
    pub fn is_mesh(self) -> bool {
        !self.is_other()
    }
}
impl From<PDUType> for u8 {
    #[must_use]
    fn from(p: PDUType) -> Self {
        p.advertisement_type()
    }
}
impl From<u8> for PDUType {
    #[must_use]
    fn from(v: u8) -> Self {
        Self::from_advertisement_type(v)
    }
}
/*
const BLE_ADV_MAX_LEN: usize = 31;
#[derive(Copy, Clone, Hash, Debug, Default)]
pub struct RawAdvertisementPDU {
    buffer: [u8; BLE_ADV_MAX_LEN],
    length: u8,
}
impl RawAdvertisementPDU {
    #[must_use]
    pub fn new_with_length(length: usize) -> Self {
        assert!(
            length <= BLE_ADV_MAX_LEN,
            "{} bytes won't fit in one adv packet",
            length
        );
        Self {
            buffer: Default::default(),
            length: length as u8,
        }
    }
    #[must_use]
    pub fn new(bytes: &[u8]) -> Self {
        let mut out = Self::new_with_length(bytes.len());
        out.data_mut().copy_from_slice(bytes);
        out
    }
    #[must_use]
    pub fn new_payload(pdu_type: PDUType, payload: &[u8]) -> Self {
        let mut out = Self::new_with_length(payload.len() + 1);
        out.buffer[0] = pdu_type.into();
        out.data_mut()[1..].copy_from_slice(payload);
        out
    }
    #[must_use]
    pub fn pdu_type(&self) -> PDUType {
        self.buffer[0].into()
    }

    #[must_use]
    pub fn len(&self) -> usize {
        usize::from(self.length)
    }

    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.length == 0
    }

    #[must_use]
    pub fn data(&self) -> &[u8] {
        &self.buffer[..self.len()]
    }

    #[must_use]
    pub fn data_mut(&mut self) -> &mut [u8] {
        let l = self.len();
        &mut self.buffer[..l]
    }
}
impl AsRef<[u8]> for RawAdvertisementPDU {
    #[must_use]
    fn as_ref(&self) -> &[u8] {
        self.data()
    }
}
impl AsMut<[u8]> for RawAdvertisementPDU {
    #[must_use]
    fn as_mut(&mut self) -> &mut [u8] {
        self.data_mut()
    }
}
impl TryFrom<RawAdvertisementPDU> for EncryptedPDU {
    type Error = ();

    fn try_from(value: RawAdvertisementPDU) -> Result<Self, Self::Error> {
        if value.pdu_type() == PDUType::Network {
            Ok(Self::from(value.as_ref()))
        } else {
            Err(())
        }
    }
}
*/
pub enum PDU {
    Network(net::EncryptedPDU),
    Beacon(beacon::PackedBeacon),
    Provisioning(provisioning::pb_adv::PackedPDU),
}
pub struct TransmitParameters {
    interval: Duration,
    times: u8,
}
pub struct OutgoingMeshPDU {
    transmit_parameters: TransmitParameters,
    pdu: PDU,
}
impl AsRef<PDU> for OutgoingMeshPDU {
    fn as_ref(&self) -> &PDU {
        &self.pdu
    }
}

pub struct IncomingPDU {
    pdu: PDU,
}
impl AsRef<PDU> for IncomingPDU {
    fn as_ref(&self) -> &PDU {
        &self.pdu
    }
}
pub struct PDUConversionError(());
impl TryFrom<&AdStructure> for PDU {
    type Error = PDUConversionError;

    fn try_from(value: &AdStructure) -> Result<Self, Self::Error> {
        match value {
            AdStructure::MeshPDU(b) => Ok(PDU::Network(
                net::EncryptedPDU::new(b.as_ref()).ok_or(PDUConversionError(()))?,
            )),
            AdStructure::MeshBeacon(_b) => unimplemented!(),
            AdStructure::MeshProvision(_b) => unimplemented!(),
            _ => Err(PDUConversionError(())),
        }
    }
}
impl From<&net::EncryptedPDU> for AdStructure {
    fn from(pdu: &EncryptedPDU) -> Self {
        AdStructure::MeshPDU(AdStructureDataBuffer::new(pdu.as_ref()))
    }
}
impl From<&beacon::PackedBeacon> for AdStructure {
    fn from(beacon: &beacon::PackedBeacon) -> Self {
        AdStructure::MeshBeacon(AdStructureDataBuffer::new(beacon.as_ref()))
    }
}
impl From<&provisioning::pb_adv::PackedPDU> for AdStructure {
    fn from(pdu: &PackedPDU) -> Self {
        AdStructure::MeshProvision(AdStructureDataBuffer::new(pdu.as_ref()))
    }
}
impl From<&PDU> for AdStructure {
    fn from(p: &PDU) -> Self {
        match p {
            PDU::Network(n) => n.into(),
            PDU::Beacon(b) => b.into(),
            PDU::Provisioning(p) => p.into(),
        }
    }
}
pub struct MeshPDUQueue<Timestamp: TimestampTrait> {
    queue: crate::scheduler::SlottedTimeQueue<OutgoingMeshPDU, Timestamp>,
}
pub struct IOError(());
pub trait IOBearer {
    fn on_io_pdu(&mut self, callback: Box<dyn FnMut(&IncomingPDU)>);
    fn send_io_pdu(&mut self, pdu: &PDU) -> Result<(), IOError>;
}
#[derive(Copy, Clone, Debug, Hash)]
pub struct PDUQueueSlot(TimeQueueSlotKey);
impl<Timestamp: TimestampTrait> MeshPDUQueue<Timestamp> {
    pub fn add(&mut self, delay: Duration, io_pdu: OutgoingMeshPDU) -> PDUQueueSlot {
        PDUQueueSlot(self.queue.push(Timestamp::with_delay(delay), io_pdu))
    }
    pub fn cancel(&mut self, slot: PDUQueueSlot) -> Option<OutgoingMeshPDU> {
        self.queue.remove(slot.0)
    }

    pub fn send_ready(&mut self, bearer: &mut impl IOBearer) -> Result<(), IOError> {
        while let Some((_, pdu)) = self.queue.pop_ready() {
            bearer.send_io_pdu(&pdu.pdu)?
        }
        Ok(())
    }
}

pub struct AdvertisementIOBearer<S: Scanner, A: Advertiser> {
    scanner: S,
    advertiser: A,
}
impl<S: Scanner, A: Advertiser> AdvertisementIOBearer<S, A> {
    pub fn new(scanner: S, advertiser: A) -> AdvertisementIOBearer<S, A> {
        AdvertisementIOBearer {
            scanner,
            advertiser,
        }
    }
}
impl<S: Scanner, A: Advertiser> IOBearer for AdvertisementIOBearer<S, A> {
    fn on_io_pdu(&mut self, mut callback: Box<dyn FnMut(&IncomingPDU)>) {
        self.scanner.on_advertisement(Box::new(move |incoming| {
            // Only look at the first AdStructure in the advertisement for now.
            if let Some(first_struct) = incoming.adv().iter().next() {
                if let Ok(pdu) = PDU::try_from(&first_struct) {
                    let incoming = IncomingPDU { pdu };
                    callback(&incoming);
                }
            }
        }));
    }

    fn send_io_pdu(&mut self, pdu: &PDU) -> Result<(), IOError> {
        self.advertiser
            .advertise(&RawAdvertisement::from(&pdu.into()))
            .map_err(|_| IOError(()))
    }
}
