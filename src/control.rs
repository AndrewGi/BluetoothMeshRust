//! Bluetooth Mesh Control Layer.

/// 7 Bit Control Opcode
#[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug)]
#[repr(u8)]
pub enum ControlOpcode {
    Ack = 0x00, // Handled by the lower transport layer.
    FriendPoll = 0x01,
    FriendUpdate = 0x02,
    FriendRequest = 0x03,
    FriendOffer = 0x04,
    FriendClear = 0x05,
    FriendClearConfirm = 0x06,
    FriendSubscriptionListAdd = 0x07,
    FriendSubscriptionListRemove = 0x08,
    FriendSubscriptionListConfirm = 0x09,
    Heartbeat = 0x0A,
}
impl ControlOpcode {
    pub fn new(opcode: u8) -> Option<Self> {
        match opcode {
            0x00 => Some(ControlOpcode::Ack),
            0x01 => Some(ControlOpcode::FriendPoll),
            0x02 => Some(ControlOpcode::FriendUpdate),
            0x03 => Some(ControlOpcode::FriendRequest),
            0x04 => Some(ControlOpcode::FriendOffer),
            0x05 => Some(ControlOpcode::FriendClear),
            0x06 => Some(ControlOpcode::FriendClearConfirm),
            0x07 => Some(ControlOpcode::FriendSubscriptionListAdd),
            0x08 => Some(ControlOpcode::FriendSubscriptionListRemove),
            0x09 => Some(ControlOpcode::FriendSubscriptionListConfirm),
            0x0A => Some(ControlOpcode::Heartbeat),
            _ => None,
        }
    }
}
impl From<ControlOpcode> for u8 {
    fn from(opcode: ControlOpcode) -> Self {
        opcode as u8
    }
}

pub struct PDU {}
