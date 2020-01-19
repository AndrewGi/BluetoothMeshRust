/// HCI Layer is Little Endian.
pub mod le;
pub mod link_control;

use core::convert::TryFrom;

#[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug)]
pub struct HCIConversionError(());
#[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug)]
#[repr(u8)]
pub enum ErrorCode {
    Ok = 0x00,
    UnknownHCICommand = 0x01,
    NoConnection = 0x02,
    HardwareFailure = 0x03,
    PageTimeout = 0x04,
    AuthenticationFailure = 0x05,
    KeyMissing = 0x06,
    MemoryFull = 0x07,
    ConnectionTimeout = 0x08,
    MaxNumberOfConnections = 0x09,
    MaxNumberOfSCOConnectionsToADevice = 0x0A,
    ACLConnectionAlreadyExists = 0x0B,
    CommandDisallowed = 0x0C,
    HostRejectedDueToLimitedResources = 0x0D,
    HostRejectedDueToSecurityReasons = 0x0E,
    HostRejectedDueToARemoteDeviceOnlyAPersonalDevice = 0x0F,
    HostTimeout = 0x10,
    UnsupportedFeatureOrParameterValue = 0x11,
    InvalidHCICommandParameters = 0x12,
    OtherEndTerminatedConnectionUserEndedConnection = 0x13,
    OtherEndTerminatedConnectionLowResources = 0x14,
    OtherEndTerminatedConnectionAboutToPowerOff = 0x15,
    ConnectionTerminatedByLocalHost = 0x16,
    RepeatedAttempts = 0x17,
    PairingNotAllowed = 0x18,
    UnknownLMPPDU = 0x19,
    UnsupportedRemoteFeature = 0x1A,
    SCOOffsetRejected = 0x1B,
    SCOIntervalRejected = 0x1C,
    SCOAirModeRejected = 0x1D,
    InvalidLMPParameters = 0x1E,
    UnspecifiedError = 0x1F,
    UnsupportedLMPParameter = 0x20,
    RoleChangeNotAllowed = 0x21,
    LMPResponseTimeout = 0x22,
    LMPErrorTransactionCollision = 0x23,
    LMPPDUNotAllowed = 0x24,
    EncryptionModeNotAcceptable = 0x25,
    UnitKeyUsed = 0x26,
    QoSNotSupported = 0x27,
    InstantPassed = 0x28,
    PairingWithUnitKeyNotSupported = 0x29,
}
impl From<ErrorCode> for u8 {
    fn from(code: ErrorCode) -> Self {
        code as u8
    }
}
impl TryFrom<u8> for ErrorCode {
    type Error = HCIConversionError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0x00 => Ok(ErrorCode::Ok),
            0x01 => Ok(ErrorCode::UnknownHCICommand),
            0x02 => Ok(ErrorCode::NoConnection),
            0x03 => Ok(ErrorCode::HardwareFailure),
            0x04 => Ok(ErrorCode::PageTimeout),
            0x05 => Ok(ErrorCode::AuthenticationFailure),
            0x06 => Ok(ErrorCode::KeyMissing),
            0x07 => Ok(ErrorCode::MemoryFull),
            0x08 => Ok(ErrorCode::ConnectionTimeout),
            0x09 => Ok(ErrorCode::MaxNumberOfConnections),
            0x0A => Ok(ErrorCode::MaxNumberOfSCOConnectionsToADevice),
            0x0B => Ok(ErrorCode::ACLConnectionAlreadyExists),
            0x0C => Ok(ErrorCode::CommandDisallowed),
            0x0D => Ok(ErrorCode::HostRejectedDueToLimitedResources),
            0x0E => Ok(ErrorCode::HostRejectedDueToSecurityReasons),
            0x0F => Ok(ErrorCode::HostRejectedDueToARemoteDeviceOnlyAPersonalDevice),
            0x10 => Ok(ErrorCode::HostTimeout),
            0x11 => Ok(ErrorCode::UnsupportedFeatureOrParameterValue),
            0x12 => Ok(ErrorCode::InvalidHCICommandParameters),
            0x13 => Ok(ErrorCode::OtherEndTerminatedConnectionUserEndedConnection),
            0x14 => Ok(ErrorCode::OtherEndTerminatedConnectionLowResources),
            0x15 => Ok(ErrorCode::OtherEndTerminatedConnectionAboutToPowerOff),
            0x16 => Ok(ErrorCode::ConnectionTerminatedByLocalHost),
            0x17 => Ok(ErrorCode::RepeatedAttempts),
            0x18 => Ok(ErrorCode::PairingNotAllowed),
            0x19 => Ok(ErrorCode::UnknownLMPPDU),
            0x1A => Ok(ErrorCode::UnsupportedRemoteFeature),
            0x1B => Ok(ErrorCode::SCOOffsetRejected),
            0x1C => Ok(ErrorCode::SCOIntervalRejected),
            0x1D => Ok(ErrorCode::SCOAirModeRejected),
            0x1E => Ok(ErrorCode::InvalidLMPParameters),
            0x1F => Ok(ErrorCode::UnspecifiedError),
            0x20 => Ok(ErrorCode::UnsupportedLMPParameter),
            0x21 => Ok(ErrorCode::RoleChangeNotAllowed),
            0x22 => Ok(ErrorCode::LMPResponseTimeout),
            0x23 => Ok(ErrorCode::LMPErrorTransactionCollision),
            0x24 => Ok(ErrorCode::LMPPDUNotAllowed),
            0x25 => Ok(ErrorCode::EncryptionModeNotAcceptable),
            0x26 => Ok(ErrorCode::UnitKeyUsed),
            0x27 => Ok(ErrorCode::QoSNotSupported),
            0x28 => Ok(ErrorCode::InstantPassed),
            0x29 => Ok(ErrorCode::PairingWithUnitKeyNotSupported),
            _ => Err(HCIConversionError(())),
        }
    }
}

pub enum EventCode {
    InquiryComplete = 0x01,
    InquiryResult = 0x02,
    ConnectionComplete = 0x03,
    ConnectionRequest = 0x04,
    DisconnectionComplete = 0x05,
    AuthenticationComplete = 0x06,
    RemoteNameRequestComplete = 0x07,
    EncryptionChange = 0x08,
    ChangeConnectionLinkKeyComplete = 0x09,
    MasterLinkKeyComplete = 0x0A,
    ReadRemoteSupportedFeaturesComplete = 0x0B,
    ReadRemoteVersionInformationComplete = 0x0C,
    QoSSetupComplete = 0x0D,
    CommandComplete = 0x0E,
    CommandStatus = 0x0F,
    FlushOccurred = 0x11,
    RoleChange = 0x12,
    NumberOfCompletedPackets = 0x13,
    ModeChange = 0x14,
    ReturnLinkKeys = 0x15,
    PINCodeRequest = 0x16,
    LinkKeyRequest = 0x17,
    LinkKeyNotification = 0x18,
    LoopbackCommand = 0x19,
    DataBufferOverflow = 0x1A,
    MaxSlotsChange = 0x1B,
    ReadClockOffsetComplete = 0x1C,
    ConnectionPacketTypeChanged = 0x1D,
    QoSViolation = 0x1E,
    PageScanRepetitionModeChange = 0x20,
    FlowSpecificationComplete = 0x21,
    InquiryResultWithRSSI = 0x22,
    ReadRemoteExtendedFeaturesComplete = 0x23,
    SynchronousConnectionComplete = 0x2C,
    SynchronousConnectionChanged = 0x2D,
    SniffSubrating = 0x2E,
    ExtendedInquiryResult = 0x2F,
    EncryptionKeyRefreshComplete = 0x30,
    IOCapabilityRequest = 0x31,
    IOCapabilityResponse = 0x32,
    UserConfirmationRequest = 0x33,
    UserPasskeyRequest = 0x34,
    RemoteOOBDataRequest = 0x35,
    SimplePairingComplete = 0x36,
    LinkSupervisionTimeoutChanged = 0x38,
    EnhancedFlushComplete = 0x39,
    UserPasskeyNotification = 0x3B,
    KeypressNotification = 0x3C,
    RemoteHostSupportedFeaturesNotification = 0x3D,
    PhysicalLinkComplete = 0x40,
    ChannelSelected = 0x41,
    DisconnectionPhysicalLinkComplete = 0x42,
    PhysicalLinkLostEarlyWarning = 0x43,
    PhysicalLinkRecovery = 0x44,
    LogicalLinkComplete = 0x45,
    DisconnectionLogicalLinkComplete = 0x46,
    FlowSpecModifyComplete = 0x47,
    NumberOfCompletedDataBlocks = 0x48,
    ShortRangeModeChangeComplete = 0x4C,
    AMPStatusChange = 0x4D,
    AMPStartTest = 0x49,
    AMPTestEnd = 0x4A,
    AMPReceiverReport = 0x4B,
    LEMeta = 0x3E,
}
impl From<EventCode> for u8 {
    fn from(code: EventCode) -> Self {
        code as u8
    }
}
impl TryFrom<u8> for EventCode {
    type Error = HCIConversionError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0x01 => Ok(EventCode::InquiryComplete),
            0x02 => Ok(EventCode::InquiryResult),
            0x03 => Ok(EventCode::ConnectionComplete),
            0x04 => Ok(EventCode::ConnectionRequest),
            0x05 => Ok(EventCode::DisconnectionComplete),
            0x06 => Ok(EventCode::AuthenticationComplete),
            0x07 => Ok(EventCode::RemoteNameRequestComplete),
            0x08 => Ok(EventCode::EncryptionChange),
            0x09 => Ok(EventCode::ChangeConnectionLinkKeyComplete),
            0x0A => Ok(EventCode::MasterLinkKeyComplete),
            0x0B => Ok(EventCode::ReadRemoteSupportedFeaturesComplete),
            0x0C => Ok(EventCode::ReadRemoteVersionInformationComplete),
            0x0D => Ok(EventCode::QoSSetupComplete),
            0x0E => Ok(EventCode::CommandComplete),
            0x0F => Ok(EventCode::CommandStatus),
            0x11 => Ok(EventCode::FlushOccurred),
            0x12 => Ok(EventCode::RoleChange),
            0x13 => Ok(EventCode::NumberOfCompletedPackets),
            0x14 => Ok(EventCode::ModeChange),
            0x15 => Ok(EventCode::ReturnLinkKeys),
            0x16 => Ok(EventCode::PINCodeRequest),
            0x17 => Ok(EventCode::LinkKeyRequest),
            0x18 => Ok(EventCode::LinkKeyNotification),
            0x19 => Ok(EventCode::LoopbackCommand),
            0x1A => Ok(EventCode::DataBufferOverflow),
            0x1B => Ok(EventCode::MaxSlotsChange),
            0x1C => Ok(EventCode::ReadClockOffsetComplete),
            0x1D => Ok(EventCode::ConnectionPacketTypeChanged),
            0x1E => Ok(EventCode::QoSViolation),
            0x20 => Ok(EventCode::PageScanRepetitionModeChange),
            0x21 => Ok(EventCode::FlowSpecificationComplete),
            0x22 => Ok(EventCode::InquiryResultWithRSSI),
            0x23 => Ok(EventCode::ReadRemoteExtendedFeaturesComplete),
            0x2C => Ok(EventCode::SynchronousConnectionComplete),
            0x2D => Ok(EventCode::SynchronousConnectionChanged),
            0x2E => Ok(EventCode::SniffSubrating),
            0x2F => Ok(EventCode::ExtendedInquiryResult),
            0x30 => Ok(EventCode::EncryptionKeyRefreshComplete),
            0x33 => Ok(EventCode::IOCapabilityRequest),
            0x32 => Ok(EventCode::IOCapabilityResponse),
            0x31 => Ok(EventCode::UserConfirmationRequest),
            0x34 => Ok(EventCode::UserPasskeyRequest),
            0x35 => Ok(EventCode::RemoteOOBDataRequest),
            0x36 => Ok(EventCode::SimplePairingComplete),
            0x38 => Ok(EventCode::LinkSupervisionTimeoutChanged),
            0x39 => Ok(EventCode::EnhancedFlushComplete),
            0x3B => Ok(EventCode::UserPasskeyNotification),
            0x3C => Ok(EventCode::KeypressNotification),
            0x3D => Ok(EventCode::RemoteHostSupportedFeaturesNotification),
            0x40 => Ok(EventCode::PhysicalLinkComplete),
            0x41 => Ok(EventCode::ChannelSelected),
            0x42 => Ok(EventCode::DisconnectionPhysicalLinkComplete),
            0x43 => Ok(EventCode::PhysicalLinkLostEarlyWarning),
            0x44 => Ok(EventCode::PhysicalLinkRecovery),
            0x45 => Ok(EventCode::LogicalLinkComplete),
            0x46 => Ok(EventCode::DisconnectionLogicalLinkComplete),
            0x47 => Ok(EventCode::FlowSpecModifyComplete),
            0x48 => Ok(EventCode::NumberOfCompletedDataBlocks),
            0x4C => Ok(EventCode::ShortRangeModeChangeComplete),
            0x4D => Ok(EventCode::AMPStatusChange),
            0x49 => Ok(EventCode::AMPStartTest),
            0x4A => Ok(EventCode::AMPTestEnd),
            0x4B => Ok(EventCode::AMPReceiverReport),
            0x3E => Ok(EventCode::LEMeta),
            _ => Err(HCIConversionError(())),
        }
    }
}

/// 6 bit OGF
#[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Debug, Hash)]
#[repr(u8)]
pub enum OGF {
    NOP = 0x00,
    LinkControl = 0x01,
    LinkPolicy = 0x02,
    HCIControlBandband = 0x03,
    InformationalParameters = 0x04,
    StatusParameters = 0x05,
    Testing = 0x06,
    LEController = 0x08,
    VendorSpecific = 0x3F,
}
pub const OCF_MAX: u16 = (1 << 10) - 1;
/// 10 bit OCF
#[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Debug, Hash)]
pub struct OCF(u16);
impl OCF {
    pub fn new(ocf: u16) -> Self {
        assert!(ocf <= OCF_MAX, "ocf bigger than 10 bits");
        Self(ocf)
    }
}
impl From<OCF> for u16 {
    fn from(ocf: OCF) -> Self {
        ocf.0
    }
}
#[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Debug, Hash)]
pub struct Opcode(pub OGF, pub OCF);
