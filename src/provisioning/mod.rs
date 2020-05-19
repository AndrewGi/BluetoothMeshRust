//! Provisioning Layer for Bluetooth Mesh
//! Provisioning is Big Endian.

pub mod beacons;
pub mod bearer;
pub mod bearer_control;
pub mod confirmation;
pub mod data;
pub mod generic;
pub mod generic_bearer;
pub mod generic_link;
pub mod link;
pub mod pb_adv;
pub mod pb_gatt;
pub mod protocol;
pub mod provisioner;

pub enum Error {
    Closed(bearer_control::CloseReason),
}
