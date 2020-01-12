//! Upper Transport Layer. Primarily focusing on segmentation and reassembly.
use crate::address::VirtualAddress;
use crate::crypto::aes::{AESCipher, Error, MicSize};
use crate::crypto::key::{AppKey, DevKey, Key};
use crate::crypto::nonce::{AppNonce, DeviceNonce, Nonce};
use crate::crypto::{AID, MIC};
use crate::lower::PDU::SegmentedAccess;
use crate::lower::{SegN, SegO, SegmentedAccessPDU, SeqZero};
use crate::provisioning::generic::SegmentIndex;
use alloc::boxed::Box;
use core::convert::TryFrom;
use core::mem;

pub enum SecurityMaterials {
    VirtualAddress(AppNonce, AppKey, VirtualAddress),
    App(AppNonce, AppKey),
    Device(DeviceNonce, DevKey),
}
impl SecurityMaterials {
    #[must_use]
    pub fn unpack(&self) -> (&Nonce, &Key, &[u8]) {
        match &self {
            SecurityMaterials::VirtualAddress(n, k, v) => {
                (n.as_ref(), k.as_ref(), v.uuid().as_ref())
            }
            SecurityMaterials::App(n, k) => (n.as_ref(), k.as_ref(), b""),
            SecurityMaterials::Device(n, k) => (n.as_ref(), k.as_ref(), b""),
        }
    }
    #[must_use]
    pub fn encrypt(&self, payload: &mut [u8], mic_size: MicSize) -> MIC {
        let (nonce, key, aad) = self.unpack();
        AESCipher::new(*key).ccm_encrypt(nonce, aad, payload, mic_size)
    }
    #[must_use]
    pub fn decrypt(&self, payload: &mut [u8], mic: MIC) -> Result<(), Error> {
        let (nonce, key, aad) = self.unpack();
        AESCipher::new(*key).ccm_decrypt(nonce, aad, payload, mic)
    }
}
pub struct AppPayload {
    data: Box<[u8]>,
}
impl AppPayload {
    /// Encrypts the Access Payload in-place. It reuses the data `Box` containing the plaintext
    /// data to hold the encrypted data.
    #[must_use]
    pub fn encrypt(self, sm: SecurityMaterials, mic_size: MicSize) -> EncryptedAppPayload {
        let mut data = self.data;
        let mic = sm.encrypt(data.as_mut(), mic_size);
        EncryptedAppPayload::new(data, mic)
    }
    #[must_use]
    pub fn payload(&self) -> &[u8] {
        self.data.as_ref()
    }
    #[must_use]
    pub fn len(&self) -> usize {
        self.data.len()
    }
    #[must_use]
    pub fn new(payload: Box<[u8]>) -> Self {
        Self { data: payload }
    }
}
pub struct EncryptedAppPayload {
    data: Box<[u8]>,
    mic: MIC,
}
const ENCRYPTED_APP_PAYLOAD_MAX_LEN: usize = 380;
impl EncryptedAppPayload {
    #[must_use]
    pub fn new(data: Box<[u8]>, mic: MIC) -> Self {
        assert!(data.len() < ENCRYPTED_APP_PAYLOAD_MAX_LEN - (mic.byte_size() + 4));
        Self { data, mic }
    }
    #[must_use]
    pub fn data(&self) -> &[u8] {
        self.data.as_ref()
    }
    #[must_use]
    pub fn mic(&self) -> MIC {
        self.mic
    }
    #[must_use]
    pub fn decrypt(self, sm: SecurityMaterials) -> Result<AppPayload, Error> {
        let mut data = self.data;
        sm.decrypt(data.as_mut(), self.mic)?;
        Ok(AppPayload::new(data))
    }
    pub fn data_len(&self) -> usize {
        self.data.len()
    }
    pub fn len(&self) -> usize {
        self.data_len() + self.mic.byte_size()
    }
    #[must_use]
    pub fn seg_n(&self) -> SegN {
        let l = self.len();
        let n = self.len() / SegmentedAccessPDU::max_seg_len();
        let n = if n * SegmentedAccessPDU::max_seg_len() * n != l {
            n + 1
        } else {
            n
        };
        SegN::new(u8::try_from(n).expect("data_len longer than ENCRYPTED_APP_PAYLOAD_MAX_LEN"))
    }
    /*
    #[must_use]
    pub fn segments(&self) -> SegmentIterator<'_> {
        SegmentIterator {
            seg_n: self.seg_n(),
            seg_o: SegO::new(0),
            data: self.data(),
            mic: self.mic,
        }
    }
    */
}
pub struct SegmentIterator<'a> {
    seq_zero: SeqZero,
    aid: AID,
    seg_n: SegN,
    seg_o: SegO,
    data: &'a [u8],
    mic: MIC,
}
impl SegmentIterator<'_> {
    pub fn is_done(&self) -> bool {
        u8::from(self.seg_n) < u8::from(self.seg_o)
    }
    pub fn pop_bytes(&mut self, amount: usize) -> Option<&[u8]> {
        if self.data.len() < amount {
            None
        } else {
            let (b, rest) = mem::replace(&mut self.data, &[]).split_at(amount);
            self.data = rest;
            Some(b)
        }
    }
}
impl Iterator for SegmentIterator<'_> {
    type Item = SegmentedAccessPDU;

    fn next(&mut self) -> Option<Self::Item> {
        if self.is_done() {
            None
        } else {
            unimplemented!()
        }
    }
}
