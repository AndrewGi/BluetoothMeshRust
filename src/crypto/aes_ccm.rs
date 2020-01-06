use aes::block_cipher_trait::BlockCipher;
use aes::Aes128;

use aead::generic_array::typenum::{U0, U10, U12, U13, U14, U16, U4, U6, U8};
use aead::generic_array::{ArrayLength, GenericArray};
use aead::{Aead, Error, NewAead};

use core::marker::PhantomData;

// Number of columns (32-bit words) comprising the state
const NB: usize = 4;
// Number of 32-bit words comprising the key
const NK: usize = 4;
const AES_BLOCK_SIZE: usize = NB * NK;
// Max additional authenticated size in bytes: 2^16 - 2^8 = 65280
const CCM_AAD_MAX_BYTES: usize = 0xFF00;
// Max message size in bytes: 2^(8L) = 2^16 = 65536
const CCM_PAYLOAD_MAX_BYTES: usize = 0x10000;

/// Marker trait for valid AES-CCM MAC tag sizes.
pub trait CcmTagSize: ArrayLength<u8> {}

impl CcmTagSize for U4 {}
impl CcmTagSize for U6 {}
impl CcmTagSize for U8 {}
impl CcmTagSize for U10 {}
impl CcmTagSize for U12 {}
impl CcmTagSize for U14 {}
impl CcmTagSize for U16 {}

/// The AES-CCM instance.
pub struct AesCcm<TagSize>
where
    TagSize: CcmTagSize,
{
    /// The AES-128 instance to use.
    cipher: Aes128,

    /// Tag size.
    tag_size: PhantomData<TagSize>,
}
/// Added the ability to clone a cipher to avoid having to recalculate the cipher from the key.
impl<TagSize: CcmTagSize> From<&Aes128> for AesCcm<TagSize> {
    fn from(cipher: &Aes128) -> Self {
        AesCcm {
            cipher: cipher.clone(),
            tag_size: PhantomData,
        }
    }
}
impl<TagSize: CcmTagSize> From<Aes128> for AesCcm<TagSize> {
    fn from(cipher: Aes128) -> Self {
        AesCcm {
            cipher,
            tag_size: PhantomData,
        }
    }
}
impl<TagSize> NewAead for AesCcm<TagSize>
where
    TagSize: CcmTagSize,
{
    type KeySize = U16;

    /// Creates a new `AesCcm`.
    fn new(key: GenericArray<u8, U16>) -> Self {
        AesCcm {
            cipher: Aes128::new(&key),
            tag_size: PhantomData,
        }
    }
}

impl<TagSize> Aead for AesCcm<TagSize>
where
    TagSize: CcmTagSize,
{
    type NonceSize = U13;
    type TagSize = TagSize;
    type CiphertextOverhead = U0;

    /// In-place CCM encryption and generation of detached authentication tag.
    fn encrypt_in_place_detached(
        &self,
        nonce: &GenericArray<u8, Self::NonceSize>,
        associated_data: &[u8],
        payload: &mut [u8],
    ) -> Result<GenericArray<u8, TagSize>, Error> {
        let alen = associated_data.len();
        let plen = payload.len();
        let tlen = TagSize::to_usize();

        // Input sanity check
        if alen >= CCM_AAD_MAX_BYTES || plen >= CCM_PAYLOAD_MAX_BYTES {
            return Err(Error);
        }

        // The sequence b for encryption is formatted as follows:
        // b = [FLAGS | nonce | counter ], where:
        //   FLAGS is 1 byte long
        //   nonce is 13 bytes long
        //   counter is 2 bytes long
        // The byte FLAGS is composed by the following 8 bits:
        //   0-2 bits: used to represent the value of q-1
        //   3-7 bits: always 0's
        let mut b = [0u8; AES_BLOCK_SIZE];
        let mut tag = [0u8; AES_BLOCK_SIZE];

        // Generating the authentication tag ----------------------------------

        // Formatting the sequence b for authentication
        b[0] = if alen > 0 { 0x40 } else { 0 } | ((tlen as u8 - 2) / 2) << 3 | 1;
        b[1..14].copy_from_slice(&nonce[..13]);
        b[14] = (plen >> 8) as u8;
        b[15] = plen as u8;

        // Computing the authentication tag using CBC-MAC
        tag.copy_from_slice(&b);
        self.cipher
            .encrypt_block(GenericArray::from_mut_slice(&mut tag));
        if alen > 0 {
            ccm_cbc_mac(&mut tag, associated_data, true, &self.cipher);
        }
        if plen > 0 {
            ccm_cbc_mac(&mut tag, payload, false, &self.cipher);
        }

        // Encryption ---------------------------------------------------------

        // Formatting the sequence b for encryption
        // q - 1 = 2 - 1 = 1
        b[0] = 1;
        b[14] = 0;
        b[15] = 0;

        // Encrypting payload using ctr mode
        ccm_ctr_mode(payload, &mut b, &self.cipher);

        // Restoring initial counter for ctr_mode (0)
        b[14] = 0;
        b[15] = 0;

        // Encrypting b and generating the tag
        self.cipher
            .encrypt_block(GenericArray::from_mut_slice(&mut b));
        let mut t = GenericArray::default();
        for i in 0..tlen {
            t[i] = tag[i] ^ b[i];
        }

        Ok(t)
    }

    /// In-place CCM decryption and verification of detached authentication
    /// tag.
    fn decrypt_in_place_detached(
        &self,
        nonce: &GenericArray<u8, Self::NonceSize>,
        associated_data: &[u8],
        payload: &mut [u8],
        tag: &GenericArray<u8, TagSize>,
    ) -> Result<(), Error> {
        let alen = associated_data.len();
        let plen = payload.len();
        let tlen = TagSize::to_usize();

        // Input sanity check
        if alen >= CCM_AAD_MAX_BYTES || plen >= CCM_PAYLOAD_MAX_BYTES {
            return Err(Error);
        }

        // The sequence b for authentication is formatted as follows:
        // b = [FLAGS | nonce | length(MAC length)], where:
        //   FLAGS is 1 byte long
        //   nonce is 13 bytes long
        //   length(MAC length) is 2 bytes long
        // The byte FLAGS is composed by the following 8 bits:
        //   0-2 bits: used to represent the value of q-1
        //   3-5 bits: MAC length (encoded as: (mlen-2)/2)
        //   6: Adata (0 if alen == 0, and 1 otherwise)
        //   7: always 0
        let mut b = [0u8; AES_BLOCK_SIZE];
        let mut t = [0u8; AES_BLOCK_SIZE];

        // Decryption ---------------------------------------------------------

        // Formatting the sequence b for decryption
        // q - 1 = 2 - 1 = 1
        b[0] = 1;
        b[1..14].copy_from_slice(&nonce[..13]);

        // Decrypting payload using ctr mode
        ccm_ctr_mode(payload, &mut b, &self.cipher);

        // Restoring initial counter value (0)
        b[14] = 0;
        b[15] = 0;

        // Encrypting b and restoring the tag from input
        self.cipher
            .encrypt_block(GenericArray::from_mut_slice(&mut b));
        for i in 0..tlen {
            t[i] = tag[i] ^ b[i];
        }

        // Verifying the authentication tag -----------------------------------

        // Formatting the sequence b for authentication
        b[0] = if alen > 0 { 0x40 } else { 0 } | ((tlen as u8 - 2) / 2) << 3 | 1;
        b[1..14].copy_from_slice(&nonce[..13]);
        b[14] = (plen >> 8) as u8;
        b[15] = plen as u8;

        // Computing the authentication tag using CBC-MAC
        self.cipher
            .encrypt_block(GenericArray::from_mut_slice(&mut b));
        if alen > 0 {
            ccm_cbc_mac(&mut b, associated_data, true, &self.cipher);
        }
        if plen > 0 {
            ccm_cbc_mac(&mut b, payload, false, &self.cipher);
        }

        // Comparing the received tag and the computed one
        use subtle::ConstantTimeEq;
        if b[..tlen].ct_eq(&t[..tlen]).unwrap_u8() == 0 {
            // Erase the decrypted buffer
            payload.iter_mut().for_each(|e| *e = 0);
            return Err(Error);
        }

        Ok(())
    }
}

/// Variation of CBC-MAC mode used in CCM.
fn ccm_cbc_mac(t: &mut [u8; 16], data: &[u8], flag: bool, cipher: &Aes128) {
    let mut dlen = data.len();

    let mut i = if flag {
        t[0] ^= (dlen >> 8) as u8;
        t[1] ^= dlen as u8;
        dlen += 2;
        2
    } else {
        0
    };
    let dlen = dlen;
    let mut data = data.iter();
    while i < dlen {
        t[i % AES_BLOCK_SIZE] ^= data.next().unwrap();
        i += 1;
        if i % AES_BLOCK_SIZE == 0 || dlen == i {
            cipher.encrypt_block(GenericArray::from_mut_slice(t));
        }
    }
}

/// Variation of CTR mode used in CCM.
///
/// The CTR mode used by CCM is slightly different than the conventional CTR
/// mode (the counter is increased before encryption, instead of after
/// encryption). Besides, it is assumed that the counter is stored in the last
/// 2 bytes of the nonce.
fn ccm_ctr_mode(payload: &mut [u8], ctr: &mut [u8], cipher: &Aes128) {
    let plen = payload.len();

    let mut buffer = [0u8; AES_BLOCK_SIZE];
    let mut nonce = [0u8; AES_BLOCK_SIZE];
    // Copy the counter to the nonce
    nonce.copy_from_slice(ctr);

    // Select the last 2 bytes of the nonce to be incremented
    let mut block_num = u16::from(nonce[14]) << 8 | u16::from(nonce[15]);
    for i in 0..plen {
        if i % AES_BLOCK_SIZE == 0 {
            block_num += 1;
            nonce[14] = (block_num >> 8) as u8;
            nonce[15] = block_num as u8;
            // Encrypt the nonce into the buffer
            buffer.copy_from_slice(&nonce);
            cipher.encrypt_block(GenericArray::from_mut_slice(&mut buffer));
        }
        // Update the output
        payload[i] ^= buffer[i % AES_BLOCK_SIZE];
    }

    // Update the counter
    ctr[14] = nonce[14];
    ctr[15] = nonce[15];
}
