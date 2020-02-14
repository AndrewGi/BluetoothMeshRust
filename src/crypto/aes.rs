//! A module for crypto AES functions. Essentially a wrapper around a 3rd party AES crypto lib
//! (aes_soft in this case). This lets the rest of the library code to not have a hard dependence
//! on any 3rd party libs. Bluetooth Mesh uses 128-bit exclusively as its Key bit size.

use crate::crypto::aes_cmac::Cmac;
use crate::crypto::key::Key;
use crate::crypto::{nonce::Nonce, Salt, MIC};
use aes::block_cipher_trait::{
    generic_array::{
        typenum::consts::{U4, U8},
        GenericArray,
    },
    BlockCipher,
};
use aes::Aes128;
use block_modes::block_padding::ZeroPadding;
use block_modes::BlockMode;

use crate::bytes::ToFromBytesEndian;
use aead::Aead;
use core::convert::TryInto;
use core::slice;

const AES_BLOCK_LEN: usize = 16;
type AesBlock = [u8; AES_BLOCK_LEN];
const ZERO_BLOCK: AesBlock = [0_u8; AES_BLOCK_LEN];
/// Returned when a key can't be used to decrypt. (Wrong Key?)
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Error;
type AesEcb = block_modes::Ecb<Aes128, ZeroPadding>;
type AesCcmBigMic = crate::crypto::aes_ccm::AesCcm<U8>;
type AesCcmSmallMic = crate::crypto::aes_ccm::AesCcm<U4>;
#[derive(Ord, PartialOrd, Eq, PartialEq, Copy, Clone, Debug, Hash)]
pub enum MicSize {
    Big,
    Small,
}
impl MicSize {
    pub fn byte_size(self) -> usize {
        match self {
            MicSize::Big => MIC::big_size(),
            MicSize::Small => MIC::small_size(),
        }
    }
    pub fn is_big(self) -> bool {
        match self {
            MicSize::Big => true,
            MicSize::Small => false,
        }
    }
}
pub struct AESCipher(Aes128);
impl AESCipher {
    #[must_use]
    pub fn new(key: Key) -> AESCipher {
        AESCipher(Aes128::new(GenericArray::from_slice(key.as_ref())))
    }
    #[must_use]
    fn cipher(&self) -> &Aes128 {
        &self.0
    }
    #[must_use]
    fn ecb_cipher(&self) -> AesEcb {
        AesEcb::new(self.cipher().clone(), &Default::default())
    }
    #[must_use]
    fn cmac_cipher(&self) -> Cmac<Aes128> {
        Cmac::from_cipher(self.cipher().clone())
    }
    #[must_use]
    fn ccm_big_mic_cipher(&self) -> AesCcmBigMic {
        self.cipher().into()
    }
    #[must_use]
    fn ccm_small_mic_cipher(&self) -> AesCcmSmallMic {
        self.cipher().into()
    }
    /// Decrypts `input` in-place with 128-bit `key` back into `input`.
    #[must_use]
    pub fn ecb_decrypt(&self, input: &mut [u8]) -> Result<(), Error> {
        self.ecb_cipher().decrypt(input).or(Err(Error))?;
        Ok(())
    }
    /// Encrypt `input` in-place with 128-bit `key` back into `input`.
    pub fn ecb_encrypt(&self, input: &mut [u8]) {
        let input_len = input.len();
        let mut ecb_cipher = self.ecb_cipher();
        // ecb encrypt input len must be a multiple of 16 but `input` might not be.
        // So we chunk the input and we encrypt all the blocks in place expect the last block gets copy.
        {
            let chunks = input.chunks_exact_mut(AES_BLOCK_LEN);
            for block_u8s in chunks {
                let block_ga = GenericArray::from_mut_slice(block_u8s);
                ecb_cipher.encrypt_blocks(slice::from_mut(block_ga));
            }
        }
        // Recalculate length aligned to block size. Integer division is used to align the len.
        let aligned_len = (input_len / AES_BLOCK_LEN) * AES_BLOCK_LEN;
        let rest = &mut input[..aligned_len];
        // If `input.len()` is not evenly divide into blocks (16 bytes), encrypt the last bit of
        // data not in place.
        if !rest.is_empty() {
            let l = rest.len();
            let mut block_buf = ZERO_BLOCK;
            block_buf[..l].copy_from_slice(rest);
            ecb_cipher.encrypt_blocks(slice::from_mut(GenericArray::from_mut_slice(
                &mut block_buf[..],
            )));
            rest.copy_from_slice(&block_buf[..l]);
        }
    }
    #[must_use]
    pub fn cmac(&self, m: &[u8]) -> Key {
        self.cmac_slice(&[m])
    }
    #[must_use]
    pub fn cmac_slice(&self, ms: &[&[u8]]) -> Key {
        let mut cmac_context = self.cmac_cipher();
        for m in ms {
            if !m.is_empty() {
                cmac_context.input(m);
            }
        }
        cmac_context
            .result()
            .code()
            .as_ref()
            .try_into()
            .expect("cmac code should be 16 bytes (SALT_LEN)")
    }
    pub fn ccm_encrypt(
        &self,
        nonce: &Nonce,
        associated_data: &[u8],
        payload: &mut [u8],
        mic_size: MicSize,
    ) -> MIC {
        let nonce = nonce.as_ref().into();
        match mic_size {
            MicSize::Big => self
                .ccm_big_mic_cipher()
                .encrypt_in_place_detached(nonce, associated_data, payload)
                .expect("payload or associated data too big")
                .as_slice()
                .try_into()
                .unwrap(),
            MicSize::Small => self
                .ccm_small_mic_cipher()
                .encrypt_in_place_detached(nonce, associated_data, payload)
                .expect("payload or associated data too big")
                .as_slice()
                .try_into()
                .unwrap(),
        }
    }
    /// AES CCM decryption of the payload. To supply no associated data, pass it an empty slice
    /// (such as `b""`). This function will return an [`Error`]
    pub fn ccm_decrypt(
        &self,
        nonce: &Nonce,
        associated_data: &[u8],
        payload: &mut [u8],
        mic: MIC,
    ) -> Result<(), Error> {
        let nonce = nonce.as_ref().into();
        match mic {
            MIC::Big(b) => self
                .ccm_small_mic_cipher()
                .decrypt_in_place_detached(
                    nonce,
                    associated_data,
                    payload,
                    b.to_bytes_be().as_ref().into(),
                )
                .or(Err(Error)),
            MIC::Small(s) => self
                .ccm_small_mic_cipher()
                .decrypt_in_place_detached(
                    nonce,
                    associated_data,
                    payload,
                    s.to_bytes_be().as_ref().into(),
                )
                .or(Err(Error)),
        }
    }
}

impl From<Key> for AESCipher {
    fn from(k: Key) -> Self {
        Self::new(k)
    }
}
impl From<Salt> for AESCipher {
    fn from(s: Salt) -> Self {
        s.as_key().into()
    }
}
