use crate::uuid::UUID;
use crate::{beacon, timestamp};
use alloc::collections::BTreeSet;

#[derive(Copy, Clone, PartialOrd, PartialEq, Ord, Eq, Hash)]
pub struct BeaconSource {
    pub beacon: beacon::UnprovisionedDeviceBeacon,
    pub last_seen: timestamp::Timestamp,
}
impl BeaconSource {
    pub fn uuid(&self) -> &UUID {
        &self.beacon.uuid
    }
}
pub struct UnprovisionedBeacons {
    beacons: BTreeSet<BeaconSource>,
}
