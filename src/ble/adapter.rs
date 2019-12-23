pub enum AdapterError {
    SomeError(),
}
pub trait Adapter {
    /// Set Bluetooth Adapter BLE advertisement data (37 bytes)
    fn set_advertisement_data(data: &[u8]) -> Result<(), AdapterError>;
}
