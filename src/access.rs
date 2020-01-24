//! Access Layer between Models and the rest of the stack (Transport, Network, etc). The most
//! surface layer of the stack.
use crate::mesh::{CompanyID, ModelID};
use crate::serializable::bytes::ToFromBytesEndian;

#[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Debug, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct SigModelID(u16);
impl SigModelID {
    pub const fn byte_len() -> usize {
        2
    }
}
#[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Debug, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct VendorModelID(u16);
impl VendorModelID {
    pub const fn byte_len() -> usize {
        CompanyID::byte_len() + 2
    }
}
#[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Debug, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum SigOpcode {
    SingleOctet(u8),
    DoubleOctet(u16),
}
impl SigOpcode {
    pub fn byte_len(&self) -> usize {
        match self {
            SigOpcode::SingleOctet(_) => 1,
            SigOpcode::DoubleOctet(_) => 2,
        }
    }
}
impl From<SigOpcode> for Opcode {
    fn from(opcode: SigOpcode) -> Self {
        Opcode::SIG(opcode)
    }
}
const VENDOR_OPCODE_MAX: u8 = (1u8 << 6) - 1;
/// 6 bit Vendor Opcode
#[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Debug, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct VendorOpcode(u8);
impl VendorOpcode {
    pub fn new(opcode: u8) -> Self {
        assert!(opcode <= VENDOR_OPCODE_MAX);
        VendorOpcode(opcode)
    }
}
#[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Debug, Hash)]
pub struct OpcodeConversationError(pub ());
#[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Debug, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum Opcode {
    SIG(SigOpcode),
    Vendor(VendorOpcode, CompanyID),
}
impl Opcode {
    pub fn company_id(&self) -> Option<CompanyID> {
        match self {
            Opcode::Vendor(_, cid) => Some(*cid),
            _ => None,
        }
    }
    pub fn is_sig(&self) -> bool {
        self.company_id().is_none()
    }
    pub fn is_vendor(&self) -> bool {
        !self.is_sig()
    }
    pub fn byte_len(&self) -> usize {
        match self {
            Opcode::SIG(o) => o.byte_len(),
            Opcode::Vendor(_, _) => 3,
        }
    }
    pub const fn max_byte_len() -> usize {
        3
    }
    pub fn unpack_from(bytes: &[u8]) -> Option<Self> {
        if bytes.is_empty() || bytes.len() > Self::max_byte_len() {
            None
        } else if bytes[0] == 0x7F {
            // This opcode is RFU
            None
        } else if bytes[0] & 0x80 == 0 {
            Some(SigOpcode::SingleOctet(bytes[0]).into())
        } else if bytes.len() > 1 && bytes[0] & 0xC0 == 0xC0 {
            let vendor_opcode = VendorOpcode::new(bytes[0] & !0xC0);
            let company_id = CompanyID(u16::from_le_bytes([bytes[1], bytes[2]]));
            Some(Opcode::Vendor(vendor_opcode, company_id))
        } else {
            None
        }
    }
}
#[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct ModelIdentifier {
    model_id: ModelID,
    company_id: Option<CompanyID>,
}
impl ModelIdentifier {
    pub fn new_sig(sig_model_id: ModelID) -> ModelIdentifier {
        ModelIdentifier {
            model_id: sig_model_id,
            company_id: None,
        }
    }
    /// Creates a new vendor model from a `ModelID` and Bluetooth `CompanyID`
    pub fn new_vendor(model_id: ModelID, company_id: CompanyID) -> ModelIdentifier {
        ModelIdentifier {
            model_id,
            company_id: Some(company_id),
        }
    }
    /// Returns the byte length of a vendor `ModelIdentifier`.
    /// (`vendor_byte_len() == ModelID::byte_len() + CompanyID::byte_len()`)
    pub const fn vendor_byte_len() -> usize {
        ModelID::byte_len() + CompanyID::byte_len()
    }
    /// Returns the byte length of a SIG `ModelIdentifier`.
    /// (`sig_byte_len() == ModelID::byte_len()`)
    pub const fn sig_byte_len() -> usize {
        ModelID::byte_len()
    }
    pub fn byte_len(&self) -> usize {
        if self.is_vendor() {
            Self::vendor_byte_len()
        } else {
            Self::sig_byte_len()
        }
    }
    /// Returns the `ModelID` of the model.
    pub fn model_id(&self) -> ModelID {
        self.model_id
    }
    /// Returns the `CompanyID` of the vendor model or `None` if it's a SIG model.
    pub fn company_id(&self) -> Option<CompanyID> {
        self.company_id
    }
    /// Returns if the `ModelIdentifier` is a SIG model.
    pub fn is_sig(&self) -> bool {
        self.company_id.is_none()
    }
    /// Returns if the `ModelIdentifier` is a vendor model.
    pub fn is_vendor(&self) -> bool {
        !self.is_sig()
    }
    /// Packs the `ModelIdentifier` into a little endian byte buffer. The `buf` must have enough
    /// room for the `ModelIdentifier`! (Usually 2 or 4 bytes).  
    /// # Panics
    /// Panics if `buf.len() < self.byte_len()`
    pub fn pack_into(&self, buf: &mut [u8]) {
        assert!(buf.len() >= self.byte_len());
        (match self.company_id {
            None => buf,
            Some(company_id) => {
                buf[..CompanyID::byte_len()].copy_from_slice(&company_id.to_bytes_le());
                &mut buf[CompanyID::byte_len()..]
            }
        }[..VendorModelID::byte_len()])
            .copy_from_slice(&self.model_id.to_bytes_le());
    }
    pub fn unpack_from(buf: &[u8]) -> Option<Self> {
        match buf.len() {
            4 => Some(Self::new_sig(ModelID::from_bytes_le(buf)?)),
            8 => Some(Self::new_vendor(
                ModelID::from_bytes_le(&buf[2..4])?,
                CompanyID::from_bytes_le(&buf[..2])?,
            )),
            _ => None,
        }
    }
}
