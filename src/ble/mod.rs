//! Generic BLE driver targeting mostly Bluetooth Advertisements. Implements the HCI layer.
pub mod adapter;
pub mod advertisement;
pub mod gap;
pub mod hci;
pub mod manager;
pub mod uri;
/// Stores Received Signal Strength Indicated as milli-dBm.
/// So -100 dBm is = `RSSI(-100_000)`
/// 0 dBm = `RSSI(0)`
/// 10.05 dBm = `RSSI(10_050)`
#[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug)]
pub struct RSSI(pub i32);
impl RSSI {
    pub fn new(milli_dbm: i32) -> RSSI {
        RSSI(milli_dbm)
    }
}
