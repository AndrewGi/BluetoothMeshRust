use crate::address::{Address, UnicastAddress};
use crate::mesh::{IVIndex, SequenceNumber, CTL, TTL};
use crate::serializable::bytes::ToFromBytesEndian;

const NONCE_LEN: usize = 13;
const ZERO_NONCE_BYTES: [u8; NONCE_LEN] = [0_u8; NONCE_LEN];
#[derive(Clone, Copy, Debug, Hash, Eq, PartialOrd, PartialEq, Ord)]
pub struct Nonce([u8; NONCE_LEN]);
impl Nonce {
    pub fn new(bytes: [u8; NONCE_LEN]) -> Nonce {
        Nonce(bytes)
    }
}
impl AsRef<[u8]> for Nonce {
    fn as_ref(&self) -> &[u8] {
        &self.0[..]
    }
}
#[derive(Clone, Copy, Debug, Hash, Eq, PartialOrd, PartialEq, Ord)]
pub struct NetworkNonce(Nonce);
impl NetworkNonce {
    pub fn new(nonce: Nonce) -> Self {
        Self(nonce)
    }
    pub fn new_bytes(bytes: [u8; NONCE_LEN]) -> Self {
        Self(Nonce(bytes))
    }
}
impl AsRef<[u8]> for NetworkNonce {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}
impl AsRef<Nonce> for NetworkNonce {
    fn as_ref(&self) -> &Nonce {
        &self.0
    }
}
#[derive(Clone, Copy, Debug, Hash, Eq, PartialOrd, PartialEq, Ord)]
pub struct AppNonce(Nonce);
impl AppNonce {
    pub fn new(nonce: Nonce) -> Self {
        Self(nonce)
    }
    pub fn new_bytes(bytes: [u8; NONCE_LEN]) -> Self {
        Self(Nonce(bytes))
    }
}
impl AsRef<[u8]> for AppNonce {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}
impl AsRef<Nonce> for AppNonce {
    fn as_ref(&self) -> &Nonce {
        &self.0
    }
}
#[derive(Clone, Copy, Debug, Hash, Eq, PartialOrd, PartialEq, Ord)]
pub struct DeviceNonce(Nonce);
impl DeviceNonce {
    pub fn new(nonce: Nonce) -> Self {
        Self(nonce)
    }
    pub fn new_bytes(bytes: [u8; NONCE_LEN]) -> Self {
        Self(Nonce(bytes))
    }
}
impl AsRef<[u8]> for DeviceNonce {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}
impl AsRef<Nonce> for DeviceNonce {
    fn as_ref(&self) -> &Nonce {
        &self.0
    }
}
#[derive(Clone, Copy, Debug, Hash, Eq, PartialOrd, PartialEq, Ord)]
pub struct ProxyNonce(Nonce);
impl ProxyNonce {
    pub fn new(nonce: Nonce) -> Self {
        Self(nonce)
    }
    pub fn new_bytes(bytes: [u8; NONCE_LEN]) -> Self {
        Self(Nonce(bytes))
    }
}
impl AsRef<Nonce> for ProxyNonce {
    fn as_ref(&self) -> &Nonce {
        &self.0
    }
}
/// Nonce Types
/// 0x04--0xFF RFU
#[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Debug, Hash)]
#[repr(u8)]
pub enum NonceType {
    Network = 0x00,
    Application = 0x01,
    Device = 0x02,
    Proxy = 0x03,
}
impl NonceType {
    pub fn as_u8(self) -> u8 {
        self as u8
    }
}

#[derive(Clone, Copy, Debug, Hash, Eq, PartialEq)]
pub struct NetworkNonceParts {
    ctl: CTL,
    ttl: TTL,
    src: UnicastAddress,
    seq: SequenceNumber,
    iv_index: IVIndex,
}

impl NetworkNonceParts {
    pub fn new(
        ctl: CTL,
        ttl: TTL,
        src: UnicastAddress,
        seq: SequenceNumber,
        iv_index: IVIndex,
    ) -> Self {
        Self {
            ctl,
            ttl,
            src,
            seq,
            iv_index,
        }
    }
    pub fn to_nonce(&self) -> NetworkNonce {
        let seq = self.seq.to_bytes_be();
        let src = self.src.to_bytes_be();
        let iv = self.iv_index.to_bytes_be();
        NetworkNonce::new_bytes([
            NonceType::Network.as_u8(),
            self.ttl.with_flag(self.ctl.0),
            seq[2],
            seq[1],
            seq[0],
            src[1],
            src[0],
            0x00,
            0x00,
            iv[3],
            iv[2],
            iv[1],
            iv[0],
        ])
    }
}

#[derive(Clone, Copy, Debug, Hash, Eq, PartialEq)]
pub struct AppNonceParts {
    aszmic: bool,
    seq: SequenceNumber,
    src: UnicastAddress,
    dst: Address,
    iv_index: IVIndex,
}

impl AppNonceParts {
    pub fn to_nonce(&self) -> AppNonce {
        let seq = self.seq.to_bytes_be();
        let src = self.src.to_bytes_be();
        let dst = self.src.to_bytes_be();
        let iv = self.iv_index.to_bytes_be();
        AppNonce::new_bytes([
            NonceType::Application.as_u8(),
            (self.aszmic as u8) << 7,
            seq[2],
            seq[1],
            seq[0],
            src[1],
            src[0],
            dst[1],
            dst[0],
            iv[3],
            iv[2],
            iv[1],
            iv[0],
        ])
    }
}

#[derive(Clone, Copy, Debug, Hash, Eq, PartialEq)]
pub struct DeviceNonceParts {
    aszmic: bool,
    seq: SequenceNumber,
    src: UnicastAddress,
    dst: Address,
    iv_index: IVIndex,
}

impl DeviceNonceParts {
    pub fn to_nonce(&self) -> DeviceNonce {
        let seq = self.seq.to_bytes_be();
        let src = self.src.to_bytes_be();
        let dst = self.src.to_bytes_be();
        let iv = self.iv_index.to_bytes_be();
        DeviceNonce::new_bytes([
            NonceType::Device.as_u8(),
            (self.aszmic as u8) << 7,
            seq[2],
            seq[1],
            seq[0],
            src[1],
            src[0],
            dst[1],
            dst[0],
            iv[3],
            iv[2],
            iv[1],
            iv[0],
        ])
    }
}

#[derive(Clone, Copy, Debug, Hash, Eq, PartialEq)]
pub struct ProxyNonceParts {
    seq: SequenceNumber,
    src: UnicastAddress,
    iv_index: IVIndex,
}

impl ProxyNonceParts {
    pub fn to_nonce(&self) -> ProxyNonce {
        let seq = self.seq.to_bytes_be();
        let src = self.src.to_bytes_be();
        let iv = self.iv_index.to_bytes_be();
        ProxyNonce::new_bytes([
            NonceType::Proxy.as_u8(),
            0x00,
            seq[2],
            seq[1],
            seq[0],
            src[1],
            src[0],
            0x00,
            0x00,
            iv[3],
            iv[2],
            iv[1],
            iv[0],
        ])
    }
}
