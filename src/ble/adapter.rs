pub enum AdapterError {
    SomeError(),
}
pub trait Adapter {
    /// Set Bluetooth Adapter BLE advertisement data (37 bytes)
    fn get_observer(data: &[u8]) -> Result<(), AdapterError>;
}
