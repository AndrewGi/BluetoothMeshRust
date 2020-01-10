use crate::crypto::materials::SecurityMaterials;
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
    security_materials: SecurityMaterials,
    io_bearer: Box<dyn IOBearer>,
}

impl Stack {
    pub fn new(io_bearer: Box<dyn IOBearer>, security_materials: SecurityMaterials) -> Self {
        Self {
            io_bearer,
            security_materials,
        }
    }
}
