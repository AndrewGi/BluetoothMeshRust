use crate::beacon;
use crate::uuid::UUID;
use driver_async::time::{Duration, Instant, InstantTrait};

#[derive(Copy, Clone, PartialEq, Eq, Hash, Debug, Ord, PartialOrd)]
pub struct BeaconSource {
    pub beacon: beacon::UnprovisionedDeviceBeacon,
    pub last_seen: Instant,
}
impl BeaconSource {
    pub fn new(beacon: beacon::UnprovisionedDeviceBeacon, last_seen: Instant) -> BeaconSource {
        BeaconSource { beacon, last_seen }
    }
    pub fn new_now(beacon: beacon::UnprovisionedDeviceBeacon) -> BeaconSource {
        BeaconSource::new(beacon, Instant::now())
    }
    pub fn uuid(&self) -> &UUID {
        &self.beacon.uuid
    }
    pub fn is_expired(&self, timeout: Duration) -> bool {
        Instant::now()
            .checked_duration_since(self.last_seen)
            .map(|d| d > timeout)
            .unwrap_or(false)
    }
}
#[derive(Clone, PartialOrd, PartialEq, Ord, Eq, Debug, Hash)]
pub struct UnprovisionedBeacons {
    pub beacons: Vec<Option<BeaconSource>>,
    pub timeout: Duration,
}
impl UnprovisionedBeacons {
    pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(30);
    pub fn new() -> UnprovisionedBeacons {
        Self::with_timeout(Self::DEFAULT_TIMEOUT)
    }
    pub fn with_timeout(timeout: Duration) -> UnprovisionedBeacons {
        UnprovisionedBeacons {
            beacons: Vec::new(),
            timeout,
        }
    }
    pub fn oldest_instant(&self) -> Instant {
        Instant::now() - self.timeout
    }
    pub fn beacons<'a>(&'a self) -> impl Iterator<Item = BeaconSource> + 'a {
        let oldest = self.oldest_instant();
        self.beacons
            .iter()
            .filter_map(move |&s| s.filter(move |b| b.last_seen < oldest))
    }
    pub fn insert(&mut self, beacon: BeaconSource) -> bool {
        for slot in self.beacons.iter_mut() {
            if slot.map(|b| b.beacon == beacon.beacon).unwrap_or(true) {
                *slot = Some(beacon);
                return false;
            }
        }
        let oldest = self.oldest_instant();
        for slot in self.beacons.iter_mut() {
            if slot.map(|b| b.last_seen < oldest).unwrap_or(true) {
                *slot = Some(beacon);
                return true;
            }
        }
        self.beacons.push(Some(beacon));
        return true;
    }
    pub fn shrink_to_fit(&mut self) {
        let oldest = self.oldest_instant();
        let mut furthest_index = 0;
        for slot in self.beacons.iter_mut().enumerate() {
            if let Some(b) = slot.1 {
                if b.last_seen < oldest {
                    *slot.1 = None
                } else {
                    furthest_index = slot.0;
                }
            }
        }
        self.beacons.resize(furthest_index, None);
    }
}
