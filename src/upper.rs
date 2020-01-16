//! Upper Transport Layer. Primarily focusing on segmentation and reassembly.
use crate::address::VirtualAddress;
use crate::crypto::aes::{AESCipher, Error, MicSize};
use crate::crypto::key::{AppKey, DevKey, Key};
use crate::crypto::nonce::{AppNonce, DeviceNonce, Nonce};
use crate::crypto::{AID, AKF, MIC};
use crate::lower::{SegN, SegO, SegmentedAccessPDU, SeqZero, UnsegmentedAccessPDU, SZMIC};
use alloc::boxed::Box;
use core::convert::TryFrom;
use core::mem;

/// Application Security Materials used to encrypt and decrypt at the application layer.
pub enum SecurityMaterials<'a> {
    VirtualAddress(AppNonce, &'a AppKey, AID, &'a VirtualAddress),
    App(AppNonce, &'a AppKey, AID),
    Device(DeviceNonce, &'a DevKey),
}
impl SecurityMaterials<'_> {
    /// Unpacks the Security Materials into a `Nonce`, `Key` and associated data.1
    #[must_use]
    pub fn unpack(&self) -> (&'_ Nonce, &'_ Key, &'_ [u8]) {
        match &self {
            SecurityMaterials::VirtualAddress(n, k, _, v) => {
                (n.as_ref(), k.as_ref(), v.uuid().as_ref())
            }
            SecurityMaterials::App(n, k, _) => (n.as_ref(), k.as_ref(), b""),
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
    #[must_use]
    pub fn akf(&self) -> AKF {
        self.aid().is_some().into()
    }
    #[must_use]
    pub fn aid(&self) -> Option<AID> {
        match self {
            SecurityMaterials::VirtualAddress(_, _, aid, _) => Some(*aid),
            SecurityMaterials::App(_, _, aid) => Some(*aid),
            SecurityMaterials::Device(_, _) => None,
        }
    }
}
/// Unencrypted Application payload.
pub struct AppPayload<Storage: AsRef<[u8]> + AsMut<[u8]>>(pub Storage);
impl<'a, Storage: AsRef<[u8]> + AsMut<[u8]>> AppPayload<Storage> {
    /// Encrypts the Access Payload in-place. It reuses the data `Box` containing the plaintext
    /// data to hold the encrypted data.
    #[must_use]
    pub fn encrypt(
        self,
        sm: &SecurityMaterials,
        mic_size: MicSize,
    ) -> EncryptedAppPayload<Storage> {
        let mut data = self.0;
        let mic = sm.encrypt(data.as_mut(), mic_size);
        EncryptedAppPayload::new(data, mic, sm.aid())
    }
    #[must_use]
    pub fn payload(&self) -> &[u8] {
        self.0.as_ref()
    }
    #[must_use]
    pub fn len(&self) -> usize {
        self.payload().len()
    }
    #[must_use]
    pub fn new(payload: Storage) -> Self {
        Self(payload)
    }
    #[must_use]
    pub fn should_segment(&self, mic_size: MicSize) -> bool {
        self.0.as_ref().len() + mic_size.byte_size() > UnsegmentedAccessPDU::max_len()
    }
}
pub fn calculate_seg_o(data_len: usize, pdu_size: usize) -> SegO {
    let l = data_len;
    let n = data_len / pdu_size;
    let n = if n * pdu_size * n != l { n + 1 } else { n };
    SegO::new(u8::try_from(n).expect("data_len longer than ENCRYPTED_APP_PAYLOAD_MAX_LEN"))
}
pub struct EncryptedAppPayload<Storage: AsRef<[u8]> + AsMut<[u8]>> {
    data: Storage,
    mic: MIC,
    aid: Option<AID>,
}
const ENCRYPTED_APP_PAYLOAD_MAX_LEN: usize = 380;
impl<Storage: AsRef<[u8]> + AsMut<[u8]>> EncryptedAppPayload<Storage> {
    #[must_use]
    pub fn new(data: Storage, mic: MIC, aid: Option<AID>) -> Self {
        assert!(
            data.as_ref().len()
                < ENCRYPTED_APP_PAYLOAD_MAX_LEN - mic.byte_size() + MIC::small_size()
        );
        Self { data, mic, aid }
    }
    #[must_use]
    pub fn akf(&self) -> AKF {
        self.aid.is_some().into()
    }
    #[must_use]
    pub fn aid(&self) -> Option<AID> {
        self.aid
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
    pub fn decrypt(self, sm: SecurityMaterials) -> Result<AppPayload<Storage>, Error> {
        let mut data = self.data;
        sm.decrypt(data.as_mut(), self.mic)?;
        Ok(AppPayload::new(data))
    }
    pub fn data_len(&self) -> usize {
        self.data().len()
    }
    pub fn len(&self) -> usize {
        self.data_len() + self.mic.byte_size()
    }
    #[must_use]
    pub fn seg_o(&self) -> SegO {
        calculate_seg_o(self.len(), SegmentedAccessPDU::max_seg_len())
    }
    pub fn should_segment(&self) -> bool {
        self.len() > UnsegmentedAccessPDU::max_len()
    }
    pub fn as_unsegmented(&self) -> Option<UnsegmentedAccessPDU> {
        if !self.should_segment() {
            None
        } else {
            Some(UnsegmentedAccessPDU::new(self.aid(), self.data()))
        }
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
// This should optimized into a stack allocation,
impl From<&UnsegmentedAccessPDU> for EncryptedAppPayload<Box<[u8]>> {
    fn from(pdu: &UnsegmentedAccessPDU) -> Self {
        let mic = pdu.mic();
        let upper_pdu = pdu.upper_pdu();
        let upper_pdu = Box::<[u8]>::from(&upper_pdu[..upper_pdu.len() - MIC::small_size()]);
        Self::new(upper_pdu, mic, pdu.aid())
    }
}
/// Generates `SegmentedAccessPDU`s from an Encrypted Payload.
pub struct SegmentIterator<'a> {
    seq_zero: SeqZero,
    aid: Option<AID>,
    seg_n: SegN,
    seg_o: SegO,
    data: &'a [u8],
    mic: MIC,
}
impl SegmentIterator<'_> {
    pub fn is_done(&self) -> bool {
        u8::from(self.seg_n) > u8::from(self.seg_o)
    }
    pub fn is_last_seg(&self) -> bool {
        u8::from(self.seg_n) == u8::from(self.seg_o)
    }
    pub fn szmic(&self) -> SZMIC {
        self.mic.is_big().into()
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
            assert!(!self.data.is_empty());
            if self.is_last_seg() {
                let seg_len = self.data.len() + self.mic.byte_size();
                debug_assert!(
                    seg_len <= SegmentedAccessPDU::max_seg_len(),
                    "too much data to fit in last segment"
                );
                let mut buf = [0_u8; SegmentedAccessPDU::max_seg_len()];
                buf[..self.data.len()].copy_from_slice(&self.data);
                self.data = &[];
                // Insert MIC on the end of the segment.
                let mic_bytes = &self.mic.mic().to_be_bytes()[..self.mic.byte_size()];
                buf[self.data.len()..self.data.len() + mic_bytes.len()].copy_from_slice(&mic_bytes);
                Some(SegmentedAccessPDU::new(
                    self.aid,
                    self.szmic(),
                    self.seq_zero,
                    self.seg_o,
                    self.seg_n,
                    &buf,
                ))
            } else {
                let aid = self.aid;
                let szmic = self.szmic();
                let seq_zero = self.seq_zero;
                let seg_o = self.seg_o;
                let seg_n = self.seg_n;
                let b = self
                    .pop_bytes(SegmentedAccessPDU::max_seg_len())
                    .expect("seg_n < seg_o so there must be at least full segment of bytes left");
                let out = Some(SegmentedAccessPDU::new(
                    aid, szmic, seq_zero, seg_o, seg_n, b,
                ));
                self.seg_n = self.seg_n.next();
                out
            }
        }
    }
}
