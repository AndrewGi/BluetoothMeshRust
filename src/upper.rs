//! Upper Transport Layer. Primarily focusing on segmentation and reassembly.
use crate::address::VirtualAddress;
use crate::control::ControlOpcode;
use crate::crypto::aes::{AESCipher, Error, MicSize};
use crate::crypto::key::{AppKey, DevKey, Key};
use crate::crypto::nonce::{AppNonce, DeviceNonce, Nonce};
use crate::crypto::{AID, AKF, MIC};
use crate::lower::{SegN, SegO, SegmentedAccessPDU, SegmentedControlPDU, UnsegmentedAccessPDU};
use crate::{control, lower};
use alloc::boxed::Box;
use core::convert::TryFrom;

#[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug)]
pub struct UpperPDUConversionError(());
pub enum PDU<Storage: AsRef<[u8]>> {
    Control(control::ControlPayload<Storage>),
    Access(EncryptedAppPayload<Storage>),
}
impl<Storage: AsRef<[u8]>> PDU<Storage> {
    pub fn max_seg_len(&self) -> usize {
        if self.is_control() {
            SegmentedControlPDU::max_seg_len()
        } else {
            SegmentedAccessPDU::max_seg_len()
        }
    }
    pub fn seg_o(&self) -> SegO {
        assert!(
            self.total_len() < ENCRYPTED_APP_PAYLOAD_MAX_LEN,
            "payload overflow"
        );
        let l = self.total_len();
        let n = l / self.max_seg_len();
        SegO::new(
            u8::try_from(if n * self.max_seg_len() != l {
                n + 1
            } else {
                n
            })
            .expect("can't send this much data"),
        )
    }
    /// Gets Segment N's data to be sent. !! THE MIC WON'T BE INCLUDED !!. Access Messages
    /// include a MIC and will have to be append to the end of the payload manually.
    /// # Panics
    /// Panics if seg_n > seg_o
    pub fn seg_n_data(&self, seg_n: SegN) -> &[u8] {
        let seg_i = u8::from(seg_n);
        assert!(seg_i <= u8::from(self.seg_o()));
        let seg_i = usize::from(seg_i);
        let max_seg = self.max_seg_len();
        &self.payload()[seg_i * max_seg..(seg_i + 1) * max_seg]
    }
    pub fn is_control(&self) -> bool {
        match self {
            PDU::Control(_) => true,
            PDU::Access(_) => false,
        }
    }
    pub fn payload(&self) -> &[u8] {
        match self {
            PDU::Control(c) => c.payload.as_ref(),
            PDU::Access(a) => a.data.as_ref(),
        }
    }
    pub fn is_access(&self) -> bool {
        !self.is_control()
    }
    pub fn payload_len(&self) -> usize {
        self.payload().len()
    }
    pub fn mic(&self) -> Option<MIC> {
        match self {
            PDU::Control(_) => None,
            PDU::Access(a) => Some(a.mic),
        }
    }
    pub fn total_len(&self) -> usize {
        self.payload_len() + self.mic().map(|mic| mic.byte_size()).unwrap_or(0)
    }
}
impl<Storage: Clone + AsRef<[u8]>> Clone for PDU<Storage> {
    fn clone(&self) -> Self {
        match self {
            PDU::Control(c) => PDU::Control((*c).clone()),
            PDU::Access(a) => PDU::Access((*a).clone()),
        }
    }
}
impl From<lower::UnsegmentedAccessPDU> for EncryptedAppPayload<Box<[u8]>> {
    fn from(pdu: UnsegmentedAccessPDU) -> Self {
        Self::new(pdu.upper_pdu().into(), pdu.mic(), pdu.aid())
    }
}
/// Application Security Materials used to encrypt and decrypt at the application layer.
pub enum SecurityMaterials<'a> {
    VirtualAddress(AppNonce, &'a AppKey, AID, &'a VirtualAddress),
    App(AppNonce, &'a AppKey, AID),
    Device(DeviceNonce, &'a DevKey),
}
impl SecurityMaterials<'_> {
    /// Unpacks the Security Materials into a `Nonce`, `Key` and associated data.
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
pub struct EncryptedAppPayload<Storage: AsRef<[u8]>> {
    data: Storage,
    mic: MIC,
    aid: Option<AID>,
}
const ENCRYPTED_APP_PAYLOAD_MAX_LEN: usize = 380;
impl<Storage: AsRef<[u8]>> EncryptedAppPayload<Storage> {
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
    pub fn decrypt(self, sm: SecurityMaterials) -> Result<AppPayload<Storage>, Error>
    where
        Storage: AsMut<[u8]>,
    {
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
impl<Storage: AsRef<[u8]> + Clone> Clone for EncryptedAppPayload<Storage> {
    fn clone(&self) -> Self {
        EncryptedAppPayload {
            data: self.data.clone(),
            mic: self.mic,
            aid: self.aid,
        }
    }
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
