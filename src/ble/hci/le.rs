use crate::ble::hci::{Command, HCICommandError, HCIConversionError, Opcode, OCF, OGF};
use core::convert::{TryFrom, TryInto};

#[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug)]
#[repr(u16)]
pub enum LEControllerOpcode {
    SetEventMask = 0x0001,
    ReadBufferSize = 0x0002,
    ReadLocalSupportedFeatures = 0x0003,
    SetRandomAddress = 0x0005,
    SetAdvertisingParameters = 0x0006,
    ReadAdvertisingChannelTxPower = 0x0007,
    SetAdvertisingData = 0x0008,
    SetScanResponseData = 0x0009,
    SetAdvertisingEnable = 0x000A,
    SetScanParameters = 0x000B,
    SetScanEnable = 0x000C,
    CreateConnection = 0x000D,
    CreateConnectionCancel = 0x000E,
    ReadWhitelistSize = 0x000F,
    ClearWhitelist = 0x0010,
    AddDeviceToWhitelist = 0x0011,
    RemoveDeviceFromWhitelist = 0x0012,
    ConnectionUpdate = 0x0013,
    SetHostChannelClassification = 0x0014,
    ReadChannelMap = 0x0015,
    ReadRemoteUsedFeatures = 0x0016,
    Encrypt = 0x0017,
    Rand = 0x0018,
    StartEncryption = 0x0019,
    LongTermKeyRequestReply = 0x001A,
    LongTermKeyRequestNegativeReply = 0x001B,
    ReadSupportedState = 0x001C,
    ReceiverTest = 0x001D,
    TransmitterTest = 0x001E,
    TestEnd = 0x001F,
}
impl TryFrom<OCF> for LEControllerOpcode {
    type Error = HCIConversionError;

    fn try_from(ocf: OCF) -> Result<Self, Self::Error> {
        match u16::from(ocf) {
            0x0001 => Ok(LEControllerOpcode::SetEventMask),
            0x0002 => Ok(LEControllerOpcode::ReadBufferSize),
            0x0003 => Ok(LEControllerOpcode::ReadLocalSupportedFeatures),
            0x0005 => Ok(LEControllerOpcode::SetRandomAddress),
            0x0006 => Ok(LEControllerOpcode::SetAdvertisingParameters),
            0x0007 => Ok(LEControllerOpcode::ReadAdvertisingChannelTxPower),
            0x0008 => Ok(LEControllerOpcode::SetAdvertisingData),
            0x0009 => Ok(LEControllerOpcode::SetScanResponseData),
            0x000A => Ok(LEControllerOpcode::SetAdvertisingEnable),
            0x000B => Ok(LEControllerOpcode::SetScanParameters),
            0x000C => Ok(LEControllerOpcode::SetScanEnable),
            0x000D => Ok(LEControllerOpcode::CreateConnection),
            0x000E => Ok(LEControllerOpcode::CreateConnectionCancel),
            0x000F => Ok(LEControllerOpcode::ReadWhitelistSize),
            0x0010 => Ok(LEControllerOpcode::ClearWhitelist),
            0x0011 => Ok(LEControllerOpcode::AddDeviceToWhitelist),
            0x0012 => Ok(LEControllerOpcode::RemoveDeviceFromWhitelist),
            0x0013 => Ok(LEControllerOpcode::ConnectionUpdate),
            0x0014 => Ok(LEControllerOpcode::SetHostChannelClassification),
            0x0015 => Ok(LEControllerOpcode::ReadChannelMap),
            0x0016 => Ok(LEControllerOpcode::ReadRemoteUsedFeatures),
            0x0017 => Ok(LEControllerOpcode::Encrypt),
            0x0018 => Ok(LEControllerOpcode::Rand),
            0x0019 => Ok(LEControllerOpcode::StartEncryption),
            0x001A => Ok(LEControllerOpcode::LongTermKeyRequestReply),
            0x001B => Ok(LEControllerOpcode::LongTermKeyRequestNegativeReply),
            0x001C => Ok(LEControllerOpcode::ReadSupportedState),
            0x001D => Ok(LEControllerOpcode::ReceiverTest),
            0x001E => Ok(LEControllerOpcode::TransmitterTest),
            0x001F => Ok(LEControllerOpcode::TestEnd),
            _ => Err(HCIConversionError(())),
        }
    }
}
impl LEControllerOpcode {
    pub const fn ogf(&self) -> OGF {
        OGF::LEController
    }
}
impl From<LEControllerOpcode> for OCF {
    fn from(opcode: LEControllerOpcode) -> Self {
        OCF::new(opcode as u16)
    }
}
impl From<LEControllerOpcode> for Opcode {
    fn from(opcode: LEControllerOpcode) -> Self {
        Opcode(OGF::LEController, opcode.into())
    }
}

pub struct SetScanEnable {
    pub is_enabled: bool,
    pub filter_duplicates: bool,
}
impl SetScanEnable {}
pub struct SetAdvertisingEnable {
    pub is_enabled: bool,
}
const ADVERTISING_DATA_MAX_LEN: usize = 0x1F;
pub struct SetAdvertisingData {
    data: [u8; ADVERTISING_DATA_MAX_LEN],
    len: u8,
}

impl Command for SetAdvertisingData {
    fn opcode() -> Opcode {
        LEControllerOpcode::SetAdvertisingData.into()
    }

    fn byte_len(&self) -> usize {
        usize::from(self.len) + 1
    }

    fn pack_into(&self, buf: &mut [u8]) -> Result<(), HCICommandError> {
        if buf.len() != self.byte_len() {
            Err(HCICommandError::BadLength)
        } else {
            buf[0] = self.len;
            let l = usize::from(self.len);
            buf[1..1 + l].copy_from_slice(&self.data[..l]);
            Ok(())
        }
    }

    fn unpack_from(buf: &[u8]) -> Result<Self, HCICommandError>
    where
        Self: Sized,
    {
        unimplemented!()
    }
}
impl SetAdvertisingData {
    pub fn new(data: &[u8]) -> SetAdvertisingData {
        assert!(data.len() <= ADVERTISING_DATA_MAX_LEN);
        let mut buf = [0_u8; ADVERTISING_DATA_MAX_LEN];
        buf[..data.len()].copy_from_slice(data);
        SetAdvertisingData {
            data: buf,
            len: data.len().try_into().expect("data max len 0x1F"),
        }
    }
}
pub enum ScanType {
    Passive = 0x00,
    Active = 0x01,
}
pub enum OwnAddressType {
    Public = 0x00,
    Random = 0x01,
    PrivateOrPublic = 0x02,
    PrivateOrRandom = 0x03,
}
pub enum ScanningFilterPolicy {
    All = 0x00,
    Whitelisted = 0x01,
    DirectedAll = 0x02,
    DirectedWhitelisted = 0x03,
}
/// Range 0x0004 --> 0x4000
/// Default 0x0010 (10 ms)
/// Time = N *  0.625 ms
/// Time Range 2.5 ms --> 10.24 s
pub struct ScanInterval(pub u16);
pub struct ScanWindow(pub u16);
