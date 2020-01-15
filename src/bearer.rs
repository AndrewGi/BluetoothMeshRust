//! Bluetooth Mesh Bearers.

use alloc::boxed::Box;

pub struct BearerError(());

pub struct IncomingNetworkPDU {}

pub trait NetworkBearer {}
pub trait BeaconBearer {}
pub trait ProvisionBearer {}
