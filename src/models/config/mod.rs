use crate::access::SigOpcode::{DoubleOctet, SingleOctet};
use crate::access::{Opcode, OpcodeConversationError};
use crate::control::ControlOpcode;
use core::convert::TryFrom;

pub mod messages;

pub enum ConfigOpcode {
    AppKeyAdd,
    AppKeyDelete,
    AppKeyGet,
    AppKeyList,
    AppKeyStatus,
    AppKeyUpdate,

    BeaconGet,
    BeaconSet,
    BeaconStatus,

    CompositionDataGet,
    CompositionDataStatus,

    DefaultTTLGet,
    DefaultTTLSet,
    DefaultTTLStatus,

    FriendGet,
    FriendSet,
    FriendStatus,

    GATTProxyGet,
    GATTProxySet,
    GATTProxyStatus,

    HeartbeatPublicationGet,
    HeartbeatPublicationSet,
    HeartbeatPublicationStatus,

    HeartbeatSubscriptionGet,
    HeartbeatSubscriptionSet,
    HeartbeatSubscriptionStatus,

    KeyRefreshPhaseGet,
    KeyRefreshPhaseSet,
    KeyRefreshPhaseStatus,

    LowPowerNodePollTimeoutGet,
    LowPowerNodePollTimeoutStatus,

    ModelAppBind,
    ModelAppStatus,
    ModelAppUnbind,

    ModelPublicationGet,
    ModelPublicationStatus,
    ModelPublicationVirtualAddressSet,
    ModelPublicationSet,

    ModelSubscriptionAdd,
    ModelSubscriptionDelete,
    ModelSubscriptionDeleteAll,
    ModelSubscriptionOverwrite,
    ModelSubscriptionStatus,
    ModelSubscriptionVirtualAddressAdd,
    ModelSubscriptionVirtualAddressDelete,
    ModelSubscriptionVirtualAddressOverwrite,

    NetKeyAdd,
    NetKeyDelete,
    NetKeyGet,
    NetKeyList,
    NetKeyStatus,
    NetKeyUpdate,

    NetworkTransmitGet,
    NetworkTransmitSet,
    NetworkTransmitStatus,

    NodeReset,
    NodeResetStatus,

    RelayGet,
    RelaySet,
    RelayStatus,

    SIGModelAppGet,
    SIGModelAppList,
    SIGModelSubscriptionGet,
    SIGModelSubscriptionList,

    VendorModelAppGet,
    VendorModelAppList,
    VendorModelSubscriptionGet,
    VendorModelSubscriptionList,

    NodeIdentityGet,
    NodeIdentitySet,
    NodeIdentityStatus,
}

impl ControlOpcode {}
impl TryFrom<Opcode> for ConfigOpcode {
    type Error = OpcodeConversationError;
    fn try_from(opcode: Opcode) -> Result<Self, OpcodeConversationError> {
        if let Opcode::SIG(opcode) = opcode {
            match opcode {
                SingleOctet(s) => match s {
                    0x00 => Ok(ConfigOpcode::AppKeyAdd),
                    0x01 => Ok(ConfigOpcode::AppKeyUpdate),
                    0x02 => Ok(ConfigOpcode::CompositionDataStatus),
                    0x03 => Ok(ConfigOpcode::ModelPublicationSet),

                    _ => Err(OpcodeConversationError(())),
                },
                DoubleOctet(d) => {
                    if d & 0xFF00 != 0x8000 {
                        Err(OpcodeConversationError(()))
                    } else {
                        match d & 0x00FF {
                            0x00 => Ok(ConfigOpcode::AppKeyDelete),
                            0x01 => Ok(ConfigOpcode::AppKeyGet),
                            0x02 => Ok(ConfigOpcode::AppKeyList),
                            0x03 => Ok(ConfigOpcode::AppKeyStatus),
                            0x08 => Ok(ConfigOpcode::CompositionDataGet),
                            0x09 => Ok(ConfigOpcode::BeaconGet),
                            0x0A => Ok(ConfigOpcode::BeaconSet),
                            0x0B => Ok(ConfigOpcode::BeaconStatus),
                            0x0C => Ok(ConfigOpcode::DefaultTTLGet),
                            0x0D => Ok(ConfigOpcode::DefaultTTLSet),
                            0x0E => Ok(ConfigOpcode::DefaultTTLStatus),
                            0x0F => Ok(ConfigOpcode::FriendGet),
                            0x10 => Ok(ConfigOpcode::FriendSet),
                            0x11 => Ok(ConfigOpcode::FriendStatus),
                            0x12 => Ok(ConfigOpcode::GATTProxyGet),
                            0x13 => Ok(ConfigOpcode::GATTProxySet),
                            0x14 => Ok(ConfigOpcode::GATTProxyStatus),
                            0x15 => Ok(ConfigOpcode::KeyRefreshPhaseGet),
                            0x16 => Ok(ConfigOpcode::KeyRefreshPhaseSet),
                            0x17 => Ok(ConfigOpcode::KeyRefreshPhaseStatus),
                            0x18 => Ok(ConfigOpcode::ModelPublicationGet),
                            0x19 => Ok(ConfigOpcode::ModelPublicationStatus),
                            0x1A => Ok(ConfigOpcode::ModelPublicationVirtualAddressSet),
                            0x1B => Ok(ConfigOpcode::ModelSubscriptionAdd),
                            0x1C => Ok(ConfigOpcode::ModelSubscriptionDelete),
                            0x1D => Ok(ConfigOpcode::ModelSubscriptionDeleteAll),
                            0x1E => Ok(ConfigOpcode::ModelSubscriptionOverwrite),
                            0x1F => Ok(ConfigOpcode::ModelSubscriptionStatus),
                            0x20 => Ok(ConfigOpcode::ModelSubscriptionVirtualAddressAdd),
                            0x21 => Ok(ConfigOpcode::ModelSubscriptionVirtualAddressDelete),
                            0x22 => Ok(ConfigOpcode::ModelSubscriptionVirtualAddressOverwrite),
                            0x23 => Ok(ConfigOpcode::NetworkTransmitGet),
                            0x24 => Ok(ConfigOpcode::NetworkTransmitSet),
                            0x25 => Ok(ConfigOpcode::NetworkTransmitStatus),
                            0x26 => Ok(ConfigOpcode::RelayGet),
                            0x27 => Ok(ConfigOpcode::RelaySet),
                            0x28 => Ok(ConfigOpcode::RelayStatus),
                            0x29 => Ok(ConfigOpcode::SIGModelSubscriptionGet),
                            0x2A => Ok(ConfigOpcode::SIGModelSubscriptionGet),
                            0x2B => Ok(ConfigOpcode::VendorModelSubscriptionGet),
                            0x2C => Ok(ConfigOpcode::VendorModelSubscriptionList),
                            0x2D => Ok(ConfigOpcode::LowPowerNodePollTimeoutGet),
                            0x2E => Ok(ConfigOpcode::LowPowerNodePollTimeoutStatus),
                            0x38 => Ok(ConfigOpcode::HeartbeatPublicationGet),
                            0x39 => Ok(ConfigOpcode::HeartbeatPublicationSet),
                            0x3A => Ok(ConfigOpcode::HeartbeatSubscriptionGet),
                            0x3B => Ok(ConfigOpcode::HeartbeatSubscriptionSet),
                            0x3C => Ok(ConfigOpcode::HeartbeatSubscriptionStatus),
                            0x3D => Ok(ConfigOpcode::ModelAppBind),
                            0x3E => Ok(ConfigOpcode::ModelAppStatus),
                            0x3F => Ok(ConfigOpcode::ModelAppUnbind),
                            0x40 => Ok(ConfigOpcode::NetKeyAdd),
                            0x41 => Ok(ConfigOpcode::NetKeyDelete),
                            0x42 => Ok(ConfigOpcode::NetKeyGet),
                            0x43 => Ok(ConfigOpcode::NetKeyList),
                            0x44 => Ok(ConfigOpcode::NetKeyStatus),
                            0x45 => Ok(ConfigOpcode::NetKeyUpdate),
                            0x46 => Ok(ConfigOpcode::NodeIdentityGet),
                            0x47 => Ok(ConfigOpcode::NodeIdentitySet),
                            0x48 => Ok(ConfigOpcode::NodeIdentityStatus),
                            0x49 => Ok(ConfigOpcode::NodeReset),
                            0x4A => Ok(ConfigOpcode::NodeResetStatus),
                            0x4B => Ok(ConfigOpcode::SIGModelAppGet),
                            0x4C => Ok(ConfigOpcode::SIGModelAppList),
                            0x4D => Ok(ConfigOpcode::VendorModelAppGet),
                            0x4E => Ok(ConfigOpcode::VendorModelAppList),
                            _ => Err(OpcodeConversationError(())),
                        }
                    }
                }
            }
        } else {
            Err(OpcodeConversationError(()))
        }
    }
}
impl From<ConfigOpcode> for Opcode {
    fn from(opcode: ConfigOpcode) -> Self {
        match opcode {
            ConfigOpcode::AppKeyAdd => SingleOctet(0x00).into(),
            ConfigOpcode::AppKeyDelete => DoubleOctet(0x8000).into(),
            ConfigOpcode::AppKeyGet => DoubleOctet(0x8001).into(),
            ConfigOpcode::AppKeyList => DoubleOctet(0x8002).into(),
            ConfigOpcode::AppKeyStatus => DoubleOctet(0x8003).into(),
            ConfigOpcode::AppKeyUpdate => SingleOctet(0x01).into(),
            ConfigOpcode::BeaconGet => DoubleOctet(0x8009).into(),
            ConfigOpcode::BeaconSet => DoubleOctet(0x800A).into(),
            ConfigOpcode::BeaconStatus => DoubleOctet(0x800B).into(),
            ConfigOpcode::CompositionDataGet => DoubleOctet(0x8008).into(),
            ConfigOpcode::CompositionDataStatus => SingleOctet(0x02).into(),
            ConfigOpcode::DefaultTTLGet => DoubleOctet(0x800C).into(),
            ConfigOpcode::DefaultTTLSet => DoubleOctet(0x800D).into(),
            ConfigOpcode::DefaultTTLStatus => DoubleOctet(0x800E).into(),
            ConfigOpcode::FriendGet => DoubleOctet(0x800F).into(),
            ConfigOpcode::FriendSet => DoubleOctet(0x8010).into(),
            ConfigOpcode::FriendStatus => DoubleOctet(0x8011).into(),
            ConfigOpcode::GATTProxyGet => DoubleOctet(0x8012).into(),
            ConfigOpcode::GATTProxySet => DoubleOctet(0x8013).into(),
            ConfigOpcode::GATTProxyStatus => DoubleOctet(0x8014).into(),
            ConfigOpcode::HeartbeatPublicationGet => DoubleOctet(0x8038).into(),
            ConfigOpcode::HeartbeatPublicationSet => DoubleOctet(0x8039).into(),
            ConfigOpcode::HeartbeatPublicationStatus => SingleOctet(0x06).into(),
            ConfigOpcode::HeartbeatSubscriptionGet => DoubleOctet(0x803A).into(),
            ConfigOpcode::HeartbeatSubscriptionSet => DoubleOctet(0x801B).into(),
            ConfigOpcode::HeartbeatSubscriptionStatus => DoubleOctet(0x801C).into(),
            ConfigOpcode::KeyRefreshPhaseGet => DoubleOctet(0x8015).into(),
            ConfigOpcode::KeyRefreshPhaseSet => DoubleOctet(0x8016).into(),
            ConfigOpcode::KeyRefreshPhaseStatus => DoubleOctet(0x8017).into(),
            ConfigOpcode::LowPowerNodePollTimeoutGet => DoubleOctet(0x802D).into(),
            ConfigOpcode::LowPowerNodePollTimeoutStatus => DoubleOctet(0x802E).into(),
            ConfigOpcode::ModelAppBind => DoubleOctet(0x803D).into(),
            ConfigOpcode::ModelAppStatus => DoubleOctet(0x803E).into(),
            ConfigOpcode::ModelAppUnbind => DoubleOctet(0x803F).into(),
            ConfigOpcode::ModelPublicationGet => DoubleOctet(0x8018).into(),
            ConfigOpcode::ModelPublicationStatus => DoubleOctet(0x8019).into(),
            ConfigOpcode::ModelPublicationVirtualAddressSet => DoubleOctet(0x801A).into(),
            ConfigOpcode::ModelPublicationSet => SingleOctet(0x03).into(),
            ConfigOpcode::ModelSubscriptionAdd => DoubleOctet(0x801B).into(),
            ConfigOpcode::ModelSubscriptionDelete => DoubleOctet(0x801C).into(),
            ConfigOpcode::ModelSubscriptionDeleteAll => DoubleOctet(0x801D).into(),
            ConfigOpcode::RelayGet => DoubleOctet(0x8026).into(),
            ConfigOpcode::RelaySet => DoubleOctet(0x8027).into(),
            ConfigOpcode::RelayStatus => DoubleOctet(0x8028).into(),
            ConfigOpcode::ModelSubscriptionOverwrite => DoubleOctet(0x801E).into(),
            ConfigOpcode::ModelSubscriptionStatus => DoubleOctet(0x801F).into(),
            ConfigOpcode::ModelSubscriptionVirtualAddressAdd => DoubleOctet(0x8020).into(),
            ConfigOpcode::ModelSubscriptionVirtualAddressDelete => DoubleOctet(0x8021).into(),
            ConfigOpcode::ModelSubscriptionVirtualAddressOverwrite => DoubleOctet(0x8022).into(),
            ConfigOpcode::NetKeyAdd => DoubleOctet(0x8040).into(),
            ConfigOpcode::NetKeyDelete => DoubleOctet(0x8041).into(),
            ConfigOpcode::NetKeyGet => DoubleOctet(0x8042).into(),
            ConfigOpcode::NetKeyList => DoubleOctet(0x8043).into(),
            ConfigOpcode::NetKeyStatus => DoubleOctet(0x8044).into(),
            ConfigOpcode::NetKeyUpdate => DoubleOctet(0x8045).into(),
            ConfigOpcode::NetworkTransmitGet => DoubleOctet(0x8023).into(),
            ConfigOpcode::NetworkTransmitSet => DoubleOctet(0x8024).into(),
            ConfigOpcode::NetworkTransmitStatus => DoubleOctet(0x8025).into(),
            ConfigOpcode::NodeReset => DoubleOctet(0x8049).into(),
            ConfigOpcode::NodeResetStatus => DoubleOctet(0x804A).into(),
            ConfigOpcode::SIGModelAppGet => DoubleOctet(0x804B).into(),
            ConfigOpcode::SIGModelAppList => DoubleOctet(0x804C).into(),
            ConfigOpcode::SIGModelSubscriptionGet => DoubleOctet(0x8029).into(),
            ConfigOpcode::SIGModelSubscriptionList => DoubleOctet(0x802A).into(),
            ConfigOpcode::VendorModelAppGet => DoubleOctet(0x804D).into(),
            ConfigOpcode::VendorModelAppList => DoubleOctet(0x804E).into(),
            ConfigOpcode::VendorModelSubscriptionGet => DoubleOctet(0x802B).into(),
            ConfigOpcode::VendorModelSubscriptionList => DoubleOctet(0x802C).into(),
            ConfigOpcode::NodeIdentityGet => DoubleOctet(0x8046).into(),
            ConfigOpcode::NodeIdentitySet => DoubleOctet(0x8047).into(),
            ConfigOpcode::NodeIdentityStatus => DoubleOctet(0x8048).into(),
        }
    }
}
