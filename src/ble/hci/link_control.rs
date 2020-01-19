use crate::ble::hci::{Opcode, OCF, OGF};

#[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Debug, Hash)]
#[repr(u16)]
pub enum LinkControlOpcode {
    Inquiry = 0x0001,
    InquiryCancel = 0x0002,
    PeriodicInquiryMode = 0x0003,
    ExitPeriodicInquiryMode = 0x0004,
    CreateConnection = 0x0005,
    Disconnect = 0x0006,
    AddSCOConnection = 0x0007,
    AcceptConnectionRequest = 0x0009,
    RejectConnectionRequest = 0x000A,
    LinkKeyRequestReply = 0x000B,
    LinkKeyRequestNegativeReply = 0x000C,
    PINCodeRequestReply = 0x000D,
    PINCodeRequestNegativeReply = 0x000E,
    ChangeConnectionPacketType = 0x000F,
    AuthenticationRequested = 0x0011,
    SetConnectionEncryption = 0x0013,
    ChangeConnectionLinkKey = 0x0015,
    MasterLinkKey = 0x0017,
    RemoteNameRequest = 0x0019,
    ReadRemoteSupportedFeatures = 0x001B,
    ReadRemoteVersionInformation = 0x001D,
    ReadClockOffset = 0x001F,
}
impl LinkControlOpcode {
    pub const fn ogf() -> OGF {
        OGF::LinkControl
    }
}
impl From<LinkControlOpcode> for OCF {
    fn from(opcode: LinkControlOpcode) -> Self {
        Self::new(opcode as u16)
    }
}
impl From<LinkControlOpcode> for Opcode {
    fn from(opcode: LinkControlOpcode) -> Self {
        Self(OGF::LinkControl, opcode.into())
    }
}
