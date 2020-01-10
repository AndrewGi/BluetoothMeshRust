use crate::uuid::UUID;

struct OOBInformation;
struct URIHash;
pub struct UnprovisionedDeviceBeacon {
    device_uuid: UUID,
    oob_information: OOBInformation,
    uri_hash: Option<URIHash>,
}
pub struct SecureNetworkBeacon {}
pub enum BeaconType {
    Unprovisioned = 0x00,
    SecureNetwork = 0x01,
}
pub enum Beacon {
    Unprovisioned(UnprovisionedDeviceBeacon),
    SecureNetwork(SecureNetworkBeacon),
}
