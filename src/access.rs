//! Access Layer between Models and the rest of the stack (Transport, Network, etc). The most
//! surface layer of the stack.
use crate::mesh::{CompanyID, ModelID};

#[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Debug, Hash)]
pub struct SigModelID(u16);
impl SigModelID {
    pub const fn byte_len() -> usize {
        2
    }
}
#[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Debug, Hash)]
pub struct VendorModelID(u16);
impl VendorModelID {
    pub const fn byte_len() -> usize {
        CompanyID::byte_len() + 2
    }
}
pub enum SigOpcode {
    SingleOctet(u8),
    DoubleOctet(u16),
}
/// 6 bit Vendor Opcode
#[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Debug, Hash)]
pub struct VendorOpcode(u8);
#[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Debug, Hash)]
pub enum Opcode {
    SIG(SigModelID),
    Vendor(VendorOpcode, CompanyID),
}
impl Opcode {
    pub fn company_id(&self) -> Option<CompanyID> {
        match self {
            _ => None,
            Opcode::Vendor(_, cid) => Some(*cid),
        }
    }
    pub fn is_sig(&self) -> bool {
        self.company_id().is_none()
    }
    pub fn is_vendor(&self) -> bool {
        !self.is_sig()
    }
}
#[derive(Copy, Clone, Eq, PartialEq)]
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
    pub fn new_vendor(model_id: ModelID, company_id: CompanyID) -> ModelIdentifier {
        ModelIdentifier {
            model_id,
            company_id: Some(company_id),
        }
    }
    pub fn model_id(&self) -> ModelID {
        self.model_id
    }
    pub fn company_id(&self) -> Option<CompanyID> {
        self.company_id
    }
    pub fn is_sig(&self) -> bool {
        self.company_id.is_none()
    }
    pub fn is_vendor(&self) -> bool {
        !self.is_sig()
    }
}
