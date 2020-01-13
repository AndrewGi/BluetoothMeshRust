//! Generic BLE driver targeting mostly Bluetooth Advertisements. Implements the HCI layer.
pub mod adapter;
pub mod advertisement;
pub mod gap;
pub mod hci;
pub mod manager;

/// Stores Received Signal Strength Indicated as dBm/10.
/// So -100 dBm is = `RSSI(-10000)`
#[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug)]
pub struct RSSI(i16);
impl RSSI {
    pub fn new(dbm_tenth: i16) -> RSSI {
        RSSI(dbm_tenth)
    }
}
