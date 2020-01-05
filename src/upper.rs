use crate::address::VirtualAddress;
use crate::crypto::aes::{AESCipher, MicSize};
use crate::crypto::key::{AppKey, DevKey, Key};
use crate::crypto::nonce::{AppNonce, DeviceNonce, Nonce};
use crate::crypto::MIC;
use alloc::boxed::Box;

pub struct AppPayload {
    data: Box<[u8]>,
}
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
}
