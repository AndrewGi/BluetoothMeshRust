//! Bluetooth Mesh Bearers.

use crate::ble::RSSI;
use crate::mesh::TransmitInterval;
use crate::provisioning::pb_adv;
use crate::{beacon, net};

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
pub trait NetworkSink {
    fn consume_pdu(&self, msg: &IncomingEncryptedNetworkPDU);
}
pub trait NetworkBearer<'sink> {
    fn send_pdu(&self, msg: &OutgoingEncryptedNetworkPDU) -> Result<(), BearerError>;
    fn take_pdu_sink(&'sink mut self, sink: &'sink dyn NetworkSink);
}
pub trait PBADVSink {
    fn consume_pb_adv(&self, msg: &pb_adv::PDU);
}
pub trait PBADVBearer<'sink> {
    fn send_pb_adv(&self, msg: &pb_adv::PDU) -> Result<(), BearerError>;
    fn take_pb_adv_sink(&'sink mut self, sink: &'sink dyn PBADVSink);
}

pub trait BeaconSink {
    fn consume_beacon(&self, beacon: &IncomingBeacon);
}
pub trait BeaconBearer<'sink> {
    fn send_beacon(&self, beacon: &beacon::BeaconPDU) -> Result<(), BearerError>;
    fn take_beacon_sink(&'sink mut self, sink: &'sink dyn BeaconSink);
}
pub trait AdvertisementBearer<'sinks>:
    NetworkBearer<'sinks> + PBADVBearer<'sinks> + BeaconBearer<'sinks>
{
}
pub trait GATTBearer {}
