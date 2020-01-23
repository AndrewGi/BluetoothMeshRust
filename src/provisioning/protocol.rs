use crate::crypto::MIC;
use crate::foundation::state::AttentionTimer;
use crate::mesh::ElementCount;
use crate::serializable::bytes::ToFromBytesEndian;
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
#[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Debug, Hash)]
pub enum PDU {
    Invite(Invite),
    Capabilities(Capabilities),
    Start(Start),
    PublicKey(PublicKey),
    InputComplete(InputComplete),
    Confirm(Confirmation),
    Random(Random),
    Data(EncryptedProvisioningData),
    Complete(Complete),
    Failed(Failed),
}
impl PDU {
    pub fn opcode(&self) -> Opcode {
        match self {
            PDU::Invite(_) => Invite::OPCODE,
            PDU::Capabilities(_) => Capabilities::OPCODE,
            PDU::Start(_) => Start::OPCODE,
            PDU::PublicKey(_) => PublicKey::OPCODE,
            PDU::InputComplete(_) => InputComplete::OPCODE,
            PDU::Confirm(_) => Confirmation::OPCODE,
            PDU::Random(_) => Random::OPCODE,
            PDU::Data(_) => EncryptedProvisioningData::OPCODE,
            PDU::Complete(_) => Complete::OPCODE,
            PDU::Failed(_) => Failed::OPCODE,
        }
    }
    pub fn pack(&self, buf: &mut [u8]) -> Result<Opcode, ProtocolPDUError> {
        match self {
            PDU::Invite(pdu) => {
                pdu.pack(buf)?;
                Ok(Opcode::Invite)
            }
            PDU::Capabilities(pdu) => {
                pdu.pack(buf)?;
                Ok(Opcode::Capabilities)
            }
            PDU::Start(pdu) => {
                pdu.pack(buf)?;
                Ok(Opcode::Start)
            }
            PDU::PublicKey(pdu) => {
                pdu.pack(buf)?;
                Ok(Opcode::PublicKey)
            }
            PDU::InputComplete(pdu) => {
                pdu.pack(buf)?;
                Ok(Opcode::InputComplete)
            }
            PDU::Confirm(pdu) => {
                pdu.pack(buf)?;
                Ok(Opcode::Confirm)
            }
            PDU::Random(pdu) => {
                pdu.pack(buf)?;
                Ok(Opcode::Random)
            }
            PDU::Data(pdu) => {
                pdu.pack(buf)?;
                Ok(Opcode::Data)
            }
            PDU::Complete(pdu) => {
                pdu.pack(buf)?;
                Ok(Opcode::Complete)
            }
            PDU::Failed(pdu) => {
                pdu.pack(buf)?;
                Ok(Opcode::Failed)
            }
        }
    }
    pub fn unpack(opcode: Opcode, buf: &[u8]) -> Result<PDU, ProtocolPDUError> {
        match opcode {
            Opcode::Invite => Ok(PDU::Invite(Invite::unpack(buf)?)),
            Opcode::Capabilities => Ok(PDU::Capabilities(Capabilities::unpack(buf)?)),
            Opcode::Start => Ok(PDU::Start(Start::unpack(buf)?)),
            Opcode::PublicKey => Ok(PDU::PublicKey(PublicKey::unpack(buf)?)),
            Opcode::InputComplete => Ok(PDU::InputComplete(InputComplete::unpack(buf)?)),
            Opcode::Confirm => Ok(PDU::Confirm(Confirmation::unpack(buf)?)),
            Opcode::Random => Ok(PDU::Random(Random::unpack(buf)?)),
            Opcode::Data => Ok(PDU::Data(EncryptedProvisioningData::unpack(buf)?)),
            Opcode::Complete => Ok(PDU::Complete(Complete::unpack(buf)?)),
            Opcode::Failed => Ok(PDU::Failed(Failed::unpack(buf)?)),
        }
    }
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
impl ProtocolPDU for Invite {
    const OPCODE: Opcode = Opcode::Invite;

    fn byte_len() -> usize {
        1
    }

    fn pack(&self, buf: &mut [u8]) -> Result<(), ProtocolPDUError> {
        if buf.len() != Self::byte_len() {
            Err(ProtocolPDUError::BadLength)
        } else {
            buf[0] = (self.0).0;
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
            Ok(Invite(AttentionTimer::new(buf[0])))
        }
    }
}
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
#[derive(Copy, Clone, PartialOrd, PartialEq, Ord, Eq, Debug, Hash)]
pub struct Algorithms(pub u16);
#[derive(Copy, Clone, PartialOrd, PartialEq, Ord, Eq, Debug, Hash)]
#[repr(u8)]
pub enum PublicKeyOption {
    NoKey = 0x00,
    OOBKey = 0x01,
}
impl From<PublicKeyOption> for u8 {
    fn from(option: PublicKeyOption) -> Self {
        option as u8
    }
}
impl TryFrom<u8> for PublicKeyOption {
    type Error = ProtocolPDUError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0x00 => Ok(PublicKeyOption::NoKey),
            0x01 => Ok(PublicKeyOption::OOBKey),
            _ => Err(ProtocolPDUError::BadBytes),
        }
    }
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
#[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Debug, Hash)]
pub enum StaticOOBOption {
    NoStaticOOB = 0x00,
    StaticOOBAvailable = 0x01,
}
impl From<StaticOOBOption> for u8 {
    fn from(option: StaticOOBOption) -> Self {
        option as u8
    }
}
impl TryFrom<u8> for StaticOOBOption {
    type Error = ProtocolPDUError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0x00 => Ok(StaticOOBOption::NoStaticOOB),
            0x01 => Ok(StaticOOBOption::StaticOOBAvailable),
            _ => Err(ProtocolPDUError::BadBytes),
        }
    }
}
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
impl TryFrom<u8> for OutputOOBAction {
    type Error = ProtocolPDUError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0x00 => Ok(OutputOOBAction::Blink),
            0x01 => Ok(OutputOOBAction::Beep),
            0x02 => Ok(OutputOOBAction::Vibrate),
            0x03 => Ok(OutputOOBAction::OutputNumeric),
            0x04 => Ok(OutputOOBAction::OutputAlphanumeric),
            _ => Err(ProtocolPDUError::BadBytes),
        }
    }
}
#[derive(Copy, Clone, PartialOrd, PartialEq, Ord, Eq, Debug, Hash)]
pub struct OutputOOBOptions(pub u16);
impl OutputOOBOptions {
    pub fn is_zero(self) -> bool {
        self.0 == 0
    }
}
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
impl TryFrom<u8> for InputOOBAction {
    type Error = ProtocolPDUError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0x00 => Ok(InputOOBAction::Push),
            0x01 => Ok(InputOOBAction::Twist),
            0x02 => Ok(InputOOBAction::InputNumber),
            0x03 => Ok(InputOOBAction::InputAlphanumeric),
            _ => Err(ProtocolPDUError::BadBytes),
        }
    }
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
impl TryFrom<u8> for AuthenticationMethodTypes {
    type Error = ProtocolPDUError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0x00 => Ok(AuthenticationMethodTypes::NoOOB),
            0x01 => Ok(AuthenticationMethodTypes::StaticOOB),
            0x02 => Ok(AuthenticationMethodTypes::OutputOOB),
            0x03 => Ok(AuthenticationMethodTypes::InputOOB),
            _ => Err(ProtocolPDUError::BadBytes),
        }
    }
}
#[derive(Copy, Clone, PartialOrd, PartialEq, Ord, Eq, Debug, Hash)]
pub enum AuthenticationMethod {
    NoOOB,
    StaticOOB,
    OutputOOB(OutputOOBAction, OOBSize),
    InputOOB(InputOOBAction, OOBSize),
}
#[derive(Copy, Clone, PartialOrd, PartialEq, Ord, Eq, Debug, Hash)]
pub struct InputOOBOptions(pub u16);

impl InputOOBOptions {
    pub fn is_zero(self) -> bool {
        self.0 == 0
    }
}
#[derive(Copy, Clone, PartialOrd, PartialEq, Ord, Eq, Debug, Hash)]
pub struct Capabilities {
    num_elements: ElementCount,
    algorithms: Algorithms,
    pub_key_option: PublicKeyOption,
    static_oob_option: StaticOOBOption,
    output_oob_size: Option<OOBSize>,
    output_oob_action: OutputOOBOptions,
    input_oob_size: Option<OOBSize>,
    input_oob_action: InputOOBOptions,
}
impl ProtocolPDU for Capabilities {
    const OPCODE: Opcode = Opcode::Capabilities;

    fn byte_len() -> usize {
        11
    }

    fn pack(&self, buf: &mut [u8]) -> Result<(), ProtocolPDUError> {
        if buf.len() != Self::byte_len() {
            Err(ProtocolPDUError::BadLength)
        } else if self.output_oob_action.is_zero() && self.output_oob_size.is_some()
            || self.input_oob_action.is_zero() && self.input_oob_size.is_some()
        {
            Err(ProtocolPDUError::BadState)
        } else {
            buf[0] = self.num_elements.0;
            buf[1..3].copy_from_slice(&self.algorithms.0.to_bytes_be());
            buf[3] = self.pub_key_option.into();
            buf[4] = self.static_oob_option.into();
            buf[5] = self.output_oob_size.map(u8::from).unwrap_or(0);
            buf[6..8].copy_from_slice(&self.output_oob_action.0.to_bytes_be());
            buf[8] = self.input_oob_size.map(u8::from).unwrap_or(0);
            buf[9..11].copy_from_slice(&self.input_oob_action.0.to_bytes_be());
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
            let num_elements = ElementCount(buf[0]);
            if num_elements.0 == 0 {
                // Needs at least 1 element
                return Err(ProtocolPDUError::BadBytes);
            }
            let algorithms = Algorithms(u16::from_bytes_be(&buf[1..3]).expect("hard coded length"));
            let pub_key_option = PublicKeyOption::try_from(buf[3])?;
            let static_oob_option = StaticOOBOption::try_from(buf[4])?;
            let output_oob_size = if buf[5] == 0 {
                None
            } else {
                Some(OOBSize::try_from(buf[5])?)
            };
            let output_oob_action =
                OutputOOBOptions(u16::from_bytes_be(&buf[6..8]).expect("hard coded length"));
            if output_oob_action.is_zero() && output_oob_size.is_some() {
                return Err(ProtocolPDUError::BadBytes);
            }
            let input_oob_size = if buf[8] == 0 {
                None
            } else {
                Some(OOBSize::try_from(buf[8])?)
            };
            let input_oob_action =
                InputOOBOptions(u16::from_bytes_be(&buf[9..11]).expect("hard coded length"));
            if input_oob_action.is_zero() && input_oob_size.is_some() {
                return Err(ProtocolPDUError::BadBytes);
            }
            Ok(Capabilities {
                num_elements,
                algorithms,
                pub_key_option,
                static_oob_option,
                output_oob_size,
                output_oob_action,
                input_oob_size,
                input_oob_action,
            })
        }
    }
}
pub const ENCRYPTED_PROVISIONING_DATA_LEN: usize = 25;

#[derive(Copy, Clone, PartialOrd, PartialEq, Ord, Eq, Debug, Hash)]
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
#[derive(Copy, Clone, PartialOrd, PartialEq, Ord, Eq, Debug, Hash)]
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
            let auth = match AuthenticationMethodTypes::try_from(buf[2])? {
                AuthenticationMethodTypes::NoOOB => {
                    if buf[3] != 0 || buf[4] != 0 {
                        return Err(ProtocolPDUError::BadBytes);
                    } else {
                        AuthenticationMethod::NoOOB
                    }
                }
                AuthenticationMethodTypes::StaticOOB => {
                    if buf[3] != 0 || buf[4] != 0 {
                        return Err(ProtocolPDUError::BadBytes);
                    } else {
                        AuthenticationMethod::StaticOOB
                    }
                }
                AuthenticationMethodTypes::OutputOOB => {
                    AuthenticationMethod::OutputOOB(buf[3].try_into()?, buf[4].try_into()?)
                }
                AuthenticationMethodTypes::InputOOB => {
                    AuthenticationMethod::InputOOB(buf[3].try_into()?, buf[4].try_into()?)
                }
            };
            Ok(Self {
                algorithm,
                public_key_type,
                auth_method: auth,
            })
        }
    }
}
#[derive(Copy, Clone, PartialOrd, PartialEq, Ord, Eq, Hash, Debug)]
#[repr(u8)]
pub enum ErrorCode {
    InvalidPDU = 0x01,
    InvalidFormat = 0x02,
    UnexpectedPDU = 0x03,
    ConfirmationFailed = 0x04,
    OutOfResources = 0x05,
    DecryptionFailed = 0x06,
    UnexpectedError = 0x07,
    CannotAssignAddress = 0x08,
}
impl From<ErrorCode> for u8 {
    fn from(code: ErrorCode) -> Self {
        code as u8
    }
}
impl TryFrom<u8> for ErrorCode {
    type Error = ProtocolPDUError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0x01 => Ok(ErrorCode::InvalidPDU),
            0x02 => Ok(ErrorCode::InvalidFormat),
            0x03 => Ok(ErrorCode::UnexpectedPDU),
            0x04 => Ok(ErrorCode::ConfirmationFailed),
            0x05 => Ok(ErrorCode::OutOfResources),
            0x06 => Ok(ErrorCode::DecryptionFailed),
            0x07 => Ok(ErrorCode::UnexpectedError),
            0x08 => Ok(ErrorCode::CannotAssignAddress),
            _ => Err(ProtocolPDUError::BadBytes),
        }
    }
}
#[derive(Copy, Clone, PartialOrd, PartialEq, Ord, Eq, Debug, Hash)]
pub struct Complete();
impl ProtocolPDU for Complete {
    const OPCODE: Opcode = Opcode::Complete;

    fn byte_len() -> usize {
        0
    }

    fn pack(&self, buf: &mut [u8]) -> Result<(), ProtocolPDUError> {
        if buf.len() != Self::byte_len() {
            Err(ProtocolPDUError::BadLength)
        } else {
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
            Ok(Complete())
        }
    }
}
#[derive(Copy, Clone, PartialOrd, PartialEq, Ord, Eq, Debug, Hash)]
pub struct Failed(pub ErrorCode);
impl ProtocolPDU for Failed {
    const OPCODE: Opcode = Opcode::Failed;

    fn byte_len() -> usize {
        1
    }

    fn pack(&self, buf: &mut [u8]) -> Result<(), ProtocolPDUError> {
        if buf.len() != Self::byte_len() {
            Err(ProtocolPDUError::BadLength)
        } else {
            buf[0] = self.0.into();
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
            Ok(Failed(buf[0].try_into()?))
        }
    }
}
#[derive(Copy, Clone, PartialOrd, PartialEq, Ord, Eq, Debug, Hash)]
pub struct InputComplete();
impl ProtocolPDU for InputComplete {
    const OPCODE: Opcode = Opcode::InputComplete;

    fn byte_len() -> usize {
        0
    }

    fn pack(&self, buf: &mut [u8]) -> Result<(), ProtocolPDUError> {
        if buf.len() != Self::byte_len() {
            Err(ProtocolPDUError::BadLength)
        } else {
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
            Ok(InputComplete())
        }
    }
}
pub const KEY_COMPONENT_LEN: usize = 32;
#[derive(Ord, PartialOrd, Eq, PartialEq, Copy, Clone, Hash, Debug, Default)]
pub struct PublicKey {
    pub x: [u8; KEY_COMPONENT_LEN],
    pub y: [u8; KEY_COMPONENT_LEN],
}
impl ProtocolPDU for PublicKey {
    const OPCODE: Opcode = Opcode::PublicKey;

    fn byte_len() -> usize {
        KEY_COMPONENT_LEN * 2
    }

    fn pack(&self, buf: &mut [u8]) -> Result<(), ProtocolPDUError> {
        if buf.len() != Self::byte_len() {
            Err(ProtocolPDUError::BadLength)
        } else {
            buf[..KEY_COMPONENT_LEN].copy_from_slice(&self.x[..]);
            buf[KEY_COMPONENT_LEN..KEY_COMPONENT_LEN * 2].copy_from_slice(&self.y[..]);
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
            let mut out = PublicKey::default();
            out.x.copy_from_slice(&buf[..KEY_COMPONENT_LEN]);
            out.y
                .copy_from_slice(&buf[KEY_COMPONENT_LEN..KEY_COMPONENT_LEN * 2]);
            Ok(out)
        }
    }
}
pub const CONFIRMATION_LEN: usize = 16;
#[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Default, Debug, Hash)]
pub struct Confirmation(pub [u8; CONFIRMATION_LEN]);
impl ProtocolPDU for Confirmation {
    const OPCODE: Opcode = Opcode::Confirm;

    fn byte_len() -> usize {
        CONFIRMATION_LEN
    }

    fn pack(&self, buf: &mut [u8]) -> Result<(), ProtocolPDUError> {
        if buf.len() != Self::byte_len() {
            Err(ProtocolPDUError::BadLength)
        } else {
            buf.copy_from_slice(&self.0[..]);
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
            let mut out = Confirmation::default();
            out.0.copy_from_slice(buf);
            Ok(out)
        }
    }
}
pub const RANDOM_LEN: usize = 16;
#[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug, Default)]
pub struct Random(pub [u8; RANDOM_LEN]);
impl ProtocolPDU for Random {
    const OPCODE: Opcode = Opcode::Random;

    fn byte_len() -> usize {
        RANDOM_LEN
    }

    fn pack(&self, buf: &mut [u8]) -> Result<(), ProtocolPDUError> {
        if buf.len() != Self::byte_len() {
            Err(ProtocolPDUError::BadLength)
        } else {
            buf.copy_from_slice(&self.0[..]);
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
            let mut out = Random::default();
            out.0.copy_from_slice(buf);
            Ok(out)
        }
    }
}
