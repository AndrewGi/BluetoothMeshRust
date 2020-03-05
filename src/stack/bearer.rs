//! Bluetooth Mesh Bearers.
use crate::btle::RSSI;
use crate::mesh::TransmitInterval;
use crate::{beacon, net};
use btle::advertisement::OutgoingAdvertisement;
use btle::advertiser::AdvertiserError;
use core::pin::Pin;
use futures_sink::Sink;

#[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Debug, Hash)]
pub enum BearerError {
    ReadyError,
    SendError,
    FlushError,
    AdvertiserError(AdvertiserError),
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
    fn from(o: &OutgoingMessage) -> Self {
        unimplemented!()
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
pub async fn send_message<Bearer: Sink<OutgoingMessage, Error = BearerError>>(
    mut bearer: Pin<&mut Bearer>,
    msg: OutgoingMessage,
) -> Result<(), BearerError> {
    futures_util::future::poll_fn(|cx| bearer.as_mut().poll_ready(cx))
        .await
        .ok()
        .ok_or(BearerError::ReadyError)?;
    bearer
        .as_mut()
        .start_send(msg)
        .ok()
        .ok_or(BearerError::SendError)?;
    futures_util::future::poll_fn(|cx| bearer.as_mut().poll_flush(cx))
        .await
        .ok()
        .ok_or(BearerError::FlushError)
}
