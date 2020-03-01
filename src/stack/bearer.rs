//! Bluetooth Mesh Bearers.
use crate::btle::RSSI;
use crate::mesh::TransmitInterval;
use crate::provisioning::pb_adv;
use crate::{beacon, net};
use core::pin::Pin;
use futures_sink::Sink;

#[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Debug, Hash)]
pub enum BearerError {
    AdvertiseError,
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
type DynamicBearer = dyn Sink<OutgoingMessage, Error = BearerError>;
pub struct BearerSink<T: AsMut<DynamicBearer> + AsRef<DynamicBearer>>(T);
impl<T: AsMut<DynamicBearer> + AsRef<DynamicBearer>> BearerSink<T> {
    pub fn pin_mut(self: Pin<&mut Self>) -> Pin<&mut DynamicBearer> {
        unsafe { self.map_unchecked_mut(|s| s.0.as_mut()) }
    }
    pub fn pin_ref(self: Pin<&Self>) -> Pin<&DynamicBearer> {
        unsafe { self.map_unchecked(|s| s.0.as_ref()) }
    }
    pub async fn send_message(self: Pin<&mut Self>, msg: OutgoingMessage) -> BearerError {
        self.pin_mut().start_send(msg);
        unimplemented!()
    }
}
