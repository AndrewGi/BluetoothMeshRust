//use super::crypto::;
use super::mesh::{CompanyID, ModelID};
use crate::crypto::key::AppKey;
use crate::{
    crypto::nonce::ApplicationNonce,
    crypto::{aes, MIC},
};
use alloc::boxed::Box;

#[derive(Copy, Clone, Eq, PartialEq)]
pub enum Opcode {
    SIG(u16),
    Vendor(u16, CompanyID),
}
impl Opcode {
    pub fn new_sig_u8(sig_opcode: u8) -> Opcode {
        Opcode(sig_opcode, None)
    }
    pub fn new_sig_u16(sig_opcode: u16) -> Opcode {
        Opcode(sig_opcode, None)
    }
    pub fn new_vendor(opcode: u8, company_id: CompanyID) -> Opcode {
        Opcode(opcode, company_id)
    }
    pub fn company_id(&self) -> Option<CompanyID> {
        *self.company_id
    }
    pub fn is_sig(&self) -> bool {
        self.company_id.is_none()
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
        ModelIdentifier(sig_model_id, None)
    }
    pub fn new_vendor(model_id: ModelID, company_id: CompanyID) -> ModelIdentifier {
        ModelIdentifier(model_id, company_id)
    }
    pub fn model_id(&self) -> ModelID {
        *self.model_id
    }
    pub fn company_id(&self) -> Option<CompanyID> {
        *self.company_id
    }
    pub fn is_sig(&self) -> bool {
        self.company_id.is_none()
    }
    pub fn is_vendor(&self) -> bool {
        !self.is_sig()
    }
}
