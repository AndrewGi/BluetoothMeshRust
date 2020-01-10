use crate::ble::gap::{Advertiser, Scanner};
use crate::mesh_io::IOBearer;
use alloc::boxed::Box;

/// Full Bluetooth Mesh Stack for
/// Layers:
/// - Access
/// - Control
/// - Upper Transport
/// - Lower Transport
/// - Network
/// - Bearer/IO
/// This stack acts as glue between the Mesh layers.
pub struct Stack {
    io_bearer: Box<dyn IOBearer>,
}

impl Stack {
    pub fn new(io_bearer: Box<dyn IOBearer>) -> Self {
        Self { io_bearer }
    }
}
