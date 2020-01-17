//! Bluetooth Mesh Bearers.

use crate::ble::RSSI;
use crate::mesh::TransmitInterval;
use crate::net;
use alloc::boxed::Box;

pub struct BearerError(());

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

pub trait NetworkBearer {}
pub trait BeaconBearer {}
pub trait ProvisionBearer {}
