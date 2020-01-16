use crate::foundation::FoundationStateError;
use crate::mesh::TransmitInterval;
use core::convert::TryFrom;

#[derive(Ord, PartialOrd, Eq, PartialEq, Copy, Clone, Hash, Debug)]
#[repr(u8)]
pub enum RelayState {
    Disabled = 0x00,
    Enabled = 0x01,
    NotSupported = 0x02,
}
impl From<RelayState> for u8 {
    fn from(state: RelayState) -> Self {
        state as u8
    }
}
impl TryFrom<u8> for RelayState {
    type Error = FoundationStateError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0x00 => Ok(RelayState::Disabled),
            0x01 => Ok(RelayState::Enabled),
            0x02 => Ok(RelayState::NotSupported),
            _ => Err(FoundationStateError(())),
        }
    }
}
impl Default for RelayState {
    fn default() -> Self {
        RelayState::Disabled
    }
}
#[derive(Ord, PartialOrd, Eq, PartialEq, Copy, Clone, Hash, Debug)]
pub struct RelayRetransmit(pub TransmitInterval);
#[derive(Ord, PartialOrd, Eq, PartialEq, Copy, Clone, Hash, Debug)]
#[repr(u8)]
pub enum SecureNetworkBeaconState {
    NotBroadcasting = 0x00,
    Broadcasting = 0x01,
}
impl From<SecureNetworkBeaconState> for u8 {
    fn from(state: SecureNetworkBeaconState) -> Self {
        state as u8
    }
}
impl TryFrom<u8> for SecureNetworkBeaconState {
    type Error = FoundationStateError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0x00 => Ok(SecureNetworkBeaconState::NotBroadcasting),
            0x01 => Ok(SecureNetworkBeaconState::Broadcasting),
            _ => Err(FoundationStateError(())),
        }
    }
}
#[derive(Ord, PartialOrd, Eq, PartialEq, Copy, Clone, Hash, Debug)]
#[repr(u8)]
pub enum GATTProxyState {
    Disabled = 0x00,
    Enabled = 0x01,
    NotSupported = 0x02,
}
impl From<GATTProxyState> for u8 {
    fn from(state: GATTProxyState) -> Self {
        state as u8
    }
}
impl TryFrom<u8> for GATTProxyState {
    type Error = FoundationStateError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0x00 => Ok(GATTProxyState::Disabled),
            0x01 => Ok(GATTProxyState::Enabled),
            0x02 => Ok(GATTProxyState::NotSupported),
            _ => Err(FoundationStateError(())),
        }
    }
}
#[derive(Ord, PartialOrd, Eq, PartialEq, Copy, Clone, Hash, Debug)]
#[repr(u8)]
pub enum NodeIdentityState {
    Stopped = 0x00,
    Running = 0x01,
    NotSupported = 0x02,
}

impl From<NodeIdentityState> for u8 {
    fn from(state: NodeIdentityState) -> Self {
        state as u8
    }
}
impl TryFrom<u8> for NodeIdentityState {
    type Error = FoundationStateError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0x00 => Ok(NodeIdentityState::Stopped),
            0x01 => Ok(NodeIdentityState::Running),
            0x02 => Ok(NodeIdentityState::NotSupported),
            _ => Err(FoundationStateError(())),
        }
    }
}
#[derive(Ord, PartialOrd, Eq, PartialEq, Copy, Clone, Hash, Debug)]
#[repr(u8)]
pub enum FriendState {
    Disabled = 0x00,
    Enabled = 0x01,
    NotSupported = 0x02,
}
impl From<FriendState> for u8 {
    fn from(state: FriendState) -> Self {
        state as u8
    }
}

impl TryFrom<u8> for FriendState {
    type Error = FoundationStateError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0x00 => Ok(FriendState::Disabled),
            0x01 => Ok(FriendState::Enabled),
            0x02 => Ok(FriendState::NotSupported),
            _ => Err(FoundationStateError(())),
        }
    }
}
#[derive(Ord, PartialOrd, Eq, PartialEq, Copy, Clone, Hash, Debug)]
#[repr(u8)]
pub enum KeyRefreshPhaseState {
    Normal = 0x00,
    First = 0x01,
    Second = 0x02,
}

impl From<KeyRefreshPhaseState> for u8 {
    fn from(state: KeyRefreshPhaseState) -> Self {
        state as u8
    }
}
impl TryFrom<u8> for KeyRefreshPhaseState {
    type Error = FoundationStateError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0x00 => Ok(KeyRefreshPhaseState::Normal),
            0x01 => Ok(KeyRefreshPhaseState::First),
            0x02 => Ok(KeyRefreshPhaseState::Second),
            _ => Err(FoundationStateError(())),
        }
    }
}
/// Used to allow the element to physical get the attention of a person (flashing, beep, etc).
#[derive(Ord, PartialOrd, Eq, PartialEq, Copy, Clone, Hash, Debug, Default)]
pub struct AttentionTimer(pub u8);
impl AttentionTimer {
    pub fn new(seconds_remaining: u8) -> Self {
        Self(seconds_remaining)
    }
    pub fn is_off(self) -> bool {
        self.0 == 0
    }
    pub fn is_on(self) -> bool {
        !self.is_off()
    }
}
#[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Debug, Hash)]
pub struct DefaultTTLState(u8);
impl DefaultTTLState {
    pub fn new(v: u8) -> DefaultTTLState {
        match Self::try_new(v) {
            None => panic!("bad DefaultTTL given"),
            Some(ttl) => ttl,
        }
    }
    /// Tries to create a new `DefaultTTL` from a u8.
    /// Will return `None` if `v==0x01 || (0x80 < v <= 0xFF)`.
    pub fn try_new(v: u8) -> Option<DefaultTTLState> {
        match v {
            0x01 => None,
            0x80..=0xFF => None,
            _ => Some(DefaultTTLState(v)),
        }
    }
}
impl From<DefaultTTLState> for u8 {
    fn from(ttl: DefaultTTLState) -> Self {
        ttl.0
    }
}

#[derive(Ord, PartialOrd, Eq, PartialEq, Copy, Clone, Hash, Debug)]
pub struct DefaultTTLStateError(());
impl TryFrom<u8> for DefaultTTLState {
    type Error = DefaultTTLStateError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        Self::try_new(value).ok_or(DefaultTTLStateError(()))
    }
}
pub struct NetworkTransmit(pub TransmitInterval);
