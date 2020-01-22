use crate::crypto::MIC;
use crate::foundation::publication::PublishPeriod;
use crate::foundation::state::AttentionTimer;
use crate::mesh::{ElementCount, ElementIndex};
use core::convert::{TryFrom, TryInto};

#[derive(Copy, Clone, PartialOrd, PartialEq, Ord, Eq, Debug, Hash)]
#[repr(u8)]
pub enum Opcode {
    Invite = 0x00,
    Capabilities = 0x01,
    Start = 0x02,
    PublicKey = 0x03,
    InputComplete = 0x04,
    Confirm = 0x05,
    Random = 0x06,
    Data = 0x07,
    Complete = 0x08,
    Failed = 0x09,
}

pub trait ProtocolPDU {
    const OPCODE: Opcode;
    fn opcode(&self) -> Opcode {
        Self::OPCODE
    }
    fn byte_len() -> usize;
    fn pack(&self, buf: &mut [u8]) -> Result<(), ProtocolPDUError>;
    fn unpack(buf: &[u8]) -> Result<Self, ProtocolPDUError>
    where
        Self: Sized;
}

impl From<Opcode> for u8 {
    fn from(opcode: Opcode) -> Self {
        opcode as u8
    }
}
impl TryFrom<u8> for Opcode {
    type Error = ProtocolPDUError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0x00 => Ok(Opcode::Invite),
            0x01 => Ok(Opcode::Capabilities),
            0x02 => Ok(Opcode::Start),
            0x03 => Ok(Opcode::PublicKey),
            0x04 => Ok(Opcode::InputComplete),
            0x05 => Ok(Opcode::Confirm),
            0x06 => Ok(Opcode::Random),
            0x07 => Ok(Opcode::Data),
            0x08 => Ok(Opcode::Complete),
            0x09 => Ok(Opcode::Failed),
            _ => Err(ProtocolPDUError::BadOpcode),
        }
    }
}
#[derive(Copy, Clone, PartialOrd, PartialEq, Ord, Eq, Debug, Hash)]
pub enum ProtocolPDUError {
    BadOpcode,
    BadState,
    BadBytes,
    BadLength,
}
#[derive(Copy, Clone, PartialOrd, PartialEq, Ord, Eq, Debug, Hash)]
pub struct Invite(pub AttentionTimer);
#[derive(Copy, Clone, PartialOrd, PartialEq, Ord, Eq, Debug, Hash)]
pub enum AlgorithmsFlags {
    FIPSP256 = 0b0,
}
impl TryFrom<u8> for AlgorithmsFlags {
    type Error = ProtocolPDUError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        if value == 0b0 {
            Ok(AlgorithmsFlags::FIPSP256)
        } else {
            Err(ProtocolPDUError::BadBytes)
        }
    }
}
impl From<AlgorithmsFlags> for u8 {
    fn from(flag: AlgorithmsFlags) -> Self {
        flag as u8
    }
}
pub struct Algorithms(pub u16);
#[derive(Copy, Clone, PartialOrd, PartialEq, Ord, Eq, Debug, Hash)]
#[repr(u8)]
pub enum PublicKeyOption {
    NoKey = 0x00,
    OOBKey = 0x01,
}
#[derive(Copy, Clone, PartialOrd, PartialEq, Ord, Eq, Debug, Hash)]
#[repr(u8)]
pub enum PublicKeyType {
    NotAvailable = 0b0,
    Available = 0b1,
}
impl TryFrom<u8> for PublicKeyType {
    type Error = ProtocolPDUError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0x00 => Ok(PublicKeyType::NotAvailable),
            0x01 => Ok(PublicKeyType::Available),
            _ => Err(ProtocolPDUError::BadBytes),
        }
    }
}
impl From<PublicKeyType> for u8 {
    fn from(public_key_type: PublicKeyType) -> Self {
        public_key_type as u8
    }
}
#[derive(Copy, Clone, PartialOrd, PartialEq, Ord, Eq, Debug, Hash)]
pub enum StaticOOBType {}
#[derive(Copy, Clone, PartialOrd, PartialEq, Ord, Eq, Debug, Hash)]
#[repr(u8)]
pub enum OutputOOBAction {
    Blink = 0x0,
    Beep = 0x1,
    Vibrate = 0x2,
    OutputNumeric = 0x3,
    OutputAlphanumeric = 0x4,
}
impl From<OutputOOBAction> for u8 {
    fn from(action: OutputOOBAction) -> Self {
        action as u8
    }
}
#[derive(Copy, Clone, PartialOrd, PartialEq, Ord, Eq, Debug, Hash)]
pub struct OutputOOBOptions(pub u8);
#[derive(Copy, Clone, PartialOrd, PartialEq, Ord, Eq, Debug, Hash)]
pub struct OOBSize(u8);
impl OOBSize {
    /// Creates a new OOBSize (either Input or Output).
    /// Valid values are in the range of (1..=8).
    /// # Panics
    /// Panics if `size > 8 || size < 1`.
    pub fn new(size: u8) -> OOBSize {
        match OOBSize::try_from(size) {
            Ok(size) => size,
            Err(_) => panic!("bad OOB size"),
        }
    }
}
impl TryFrom<u8> for OOBSize {
    type Error = ProtocolPDUError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0x1..=0x08 => Ok(OOBSize(value)),
            _ => Err(ProtocolPDUError::BadBytes),
        }
    }
}
impl From<OOBSize> for u8 {
    fn from(size: OOBSize) -> Self {
        size.0
    }
}
#[derive(Copy, Clone, PartialOrd, PartialEq, Ord, Eq, Debug, Hash)]
#[repr(u8)]
pub enum InputOOBAction {
    Push = 0x0,
    Twist = 0x1,
    InputNumber = 0x2,
    InputAlphanumeric = 0x3,
}

impl From<InputOOBAction> for u8 {
    fn from(action: InputOOBAction) -> Self {
        action as u8
    }
}
#[derive(Copy, Clone, PartialOrd, PartialEq, Ord, Eq, Debug, Hash)]
#[repr(u8)]
pub enum AuthenticationMethodTypes {
    NoOOB = 0x00,
    StaticOOB = 0x01,
    OutputOOB = 0x02,
    InputOOB = 0x03,
}
impl From<AuthenticationMethodTypes> for u8 {
    fn from(method: AuthenticationMethodTypes) -> Self {
        method as u8
    }
}
#[derive(Copy, Clone, PartialOrd, PartialEq, Ord, Eq, Debug, Hash)]
pub enum AuthenticationMethod {
    NoOOB,
    StaticOOB,
    OutputOOB(OutputOOBAction, OOBSize),
    InputOOB(InputOOBAction, OOBSize),
}
pub struct InputOOBOptions(pub u8);
pub struct Capabilities {
    num_elements: ElementCount,
    algorithms: Algorithms,
    pub_key_type: PublishPeriod,
}
pub const ENCRYPTED_PROVISIONING_DATA_LEN: usize = 25;
pub struct EncryptedProvisioningData {
    data: [u8; ENCRYPTED_PROVISIONING_DATA_LEN],
    mic: MIC,
}
impl ProtocolPDU for EncryptedProvisioningData {
    const OPCODE: Opcode = Opcode::Data;

    fn byte_len() -> usize {
        ENCRYPTED_PROVISIONING_DATA_LEN + MIC::big_size()
    }

    fn pack(&self, buf: &mut [u8]) -> Result<(), ProtocolPDUError> {
        if buf.len() != Self::byte_len() {
            Err(ProtocolPDUError::BadLength)
        } else {
            debug_assert!(self.mic.is_big());
            buf[..ENCRYPTED_PROVISIONING_DATA_LEN].copy_from_slice(&self.data[..]);
            self.mic
                .be_pack_into(&mut buf[ENCRYPTED_PROVISIONING_DATA_LEN..]);
            Ok(())
        }
    }

    fn unpack(buf: &[u8]) -> Result<Self, ProtocolPDUError>
    where
        Self: Sized,
    {
        if buf.len() != Self::byte_len() {
            Err(ProtocolPDUError::BadLength)
        } else {
            let mut out = [0_u8; ENCRYPTED_PROVISIONING_DATA_LEN];
            out.copy_from_slice(&buf[..ENCRYPTED_PROVISIONING_DATA_LEN]);
            let mic = MIC::try_from_bytes_be(&buf[ENCRYPTED_PROVISIONING_DATA_LEN..])
                .expect("MIC should be here");
            Ok(EncryptedProvisioningData { data: out, mic })
        }
    }
}
pub struct Start {
    algorithm: AlgorithmsFlags,
    public_key_type: PublicKeyType,
    auth_method: AuthenticationMethod,
}
impl ProtocolPDU for Start {
    const OPCODE: Opcode = Opcode::Start;

    fn byte_len() -> usize {
        5
    }

    fn pack(&self, buf: &mut [u8]) -> Result<(), ProtocolPDUError> {
        if buf.len() != Self::byte_len() {
            Err(ProtocolPDUError::BadLength)
        } else {
            buf[0] = self.algorithm.into();
            buf[1] = self.public_key_type.into();
            match self.auth_method {
                AuthenticationMethod::NoOOB => {
                    buf[2] = AuthenticationMethodTypes::NoOOB.into();
                    buf[3] = 0x00;
                    buf[4] = 0x00;
                }
                AuthenticationMethod::StaticOOB => {
                    buf[2] = AuthenticationMethodTypes::StaticOOB.into();
                    buf[3] = 0x00;
                    buf[4] = 0x00;
                }
                AuthenticationMethod::OutputOOB(action, size) => {
                    buf[2] = AuthenticationMethodTypes::OutputOOB.into();
                    buf[3] = action.into();
                    buf[4] = size.into();
                }
                AuthenticationMethod::InputOOB(action, size) => {
                    buf[2] = AuthenticationMethodTypes::InputOOB.into();
                    buf[3] = action.into();
                    buf[4] = size.into();
                }
            }
            Ok(())
        }
    }

    fn unpack(buf: &[u8]) -> Result<Self, ProtocolPDUError>
    where
        Self: Sized,
    {
        if buf.len() != Self::byte_len() {
            Err(ProtocolPDUError::BadLength)
        } else {
            let algorithm = AlgorithmsFlags::try_from(buf[0])?;
            let public_key_type = PublicKeyType::try_from(buf[1])?;
            unimplemented!()
        }
    }
}
#[derive(Copy, Clone, PartialOrd, PartialEq, Ord, Eq, Hash, Debug)]
#[repr(u8)]
pub enum ErrorCode {
    InvalidPDU = 0x01,
    InvalidFormat = 0x02,
    UnexpectPDU = 0x03,
    ConfirmationFailed = 0x04,
    OutOfResources = 0x05,
    DecryptionFailed = 0x06,
    UnexpectError = 0x07,
    CannotAssignAddress = 0x08,
}
impl From<ErrorCode> for u8 {
    fn from(code: ErrorCode) -> Self {
        code as u8
    }
}
pub struct Complete();
pub struct Failed(pub ErrorCode);
pub struct InputComplete();
pub const KEY_COMPONENT_LEN: usize = 32;
pub struct PublicKey {
    pub x: [u8; KEY_COMPONENT_LEN],
    pub y: [u8; KEY_COMPONENT_LEN],
}
pub const CONFIRMATION_LEN: usize = 16;
pub struct Confirmation(pub [u8; CONFIRMATION_LEN]);
pub const RANDOM_LEN: usize = 16;
pub struct Random(pub [u8; RANDOM_LEN]);
