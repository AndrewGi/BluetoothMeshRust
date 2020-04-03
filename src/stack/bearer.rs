//! Bluetooth Mesh Bearers.
use crate::mesh::TransmitInterval;
use crate::{beacon, net};
use btle::asyncs::poll_function::poll_fn;
use btle::le::adapter;
use btle::le::advertisement::OutgoingAdvertisement;
use btle::le::report::ReportInfo;
use btle::RSSI;
use core::pin::Pin;
use futures_core::Stream;
use futures_sink::Sink;

#[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Debug, Hash)]
pub enum BearerError {
    ReadyError,
    SendError,
    FlushError,
    AdapterError(adapter::Error),
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
