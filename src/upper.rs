use crate::address::VirtualAddress;
use crate::crypto::aes::{AESCipher, Error, MicSize};
use crate::crypto::key::{AppKey, DevKey, Key};
use crate::crypto::nonce::{AppNonce, DeviceNonce, Nonce};
use crate::crypto::MIC;
use alloc::boxed::Box;

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
impl EncryptedAppPayload {
    #[must_use]
    pub fn new(data: Box<[u8]>, mic: MIC) -> Self {
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
}
