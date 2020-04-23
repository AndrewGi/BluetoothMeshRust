//! Bluetooth Mesh Bearers.
use crate::mesh::TransmitInterval;
use crate::{beacon, net};
use btle::le::advertisement::OutgoingAdvertisement;
use btle::RSSI;
#[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Debug, Hash)]
pub enum BearerError {
    ReadyError,
    SendError,
    FlushError,
}

#[derive(Copy, Clone)]
pub struct IncomingEncryptedNetworkPDU {
    pub encrypted_pdu: net::OwnedEncryptedPDU,
    pub rssi: Option<RSSI>,
    pub dont_relay: bool,
}
impl IncomingEncryptedNetworkPDU {}

#[derive(Copy, Clone)]
pub struct OutgoingEncryptedNetworkPDU {
    pub transmit_parameters: TransmitInterval,
    pub pdu: net::OwnedEncryptedPDU,
}
pub struct IncomingBeacon {
    pub beacon: beacon::BeaconPDU,
    pub rssi: Option<RSSI>,
}
pub enum OutgoingMessage {
    Network(OutgoingEncryptedNetworkPDU),
}
impl From<&OutgoingMessage> for OutgoingAdvertisement {
    fn from(_: &OutgoingMessage) -> Self {
        todo!("implement outgoing messages")
    }
}
impl From<OutgoingMessage> for OutgoingAdvertisement {
    fn from(o: OutgoingMessage) -> Self {
        (&o).into()
    }
}
pub enum IncomingMessage {
    Network(IncomingEncryptedNetworkPDU),
}
