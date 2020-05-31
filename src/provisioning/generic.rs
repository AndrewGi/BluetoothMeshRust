//! Generic Provisioning PDUs should be sent with delays of 20-50 milliseconds between them
use super::bearer_control;

use crate::provisioning::protocol;
use btle::bytes::Storage;
use btle::PackError;
use core::convert::{TryFrom, TryInto};

/// 6 bit Segment Number
#[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Debug, Default, Hash)]
pub struct SegmentIndex(u8);
const SEGMENT_INDEX_MAX: u8 = (1_u8 << 6) - 1;
impl SegmentIndex {
    pub const ZERO: SegmentIndex = SegmentIndex(0);
    pub const MAX_SEGMENTS: u8 = SEGMENT_INDEX_MAX + 1;
    /// Creates a new 6 bit Segment Index from a u8.
    /// # Panics
    /// Panics if `index` is greater than 6 bits (`index` > `SEGMENT_INDEX_MAX`).
    pub fn new(index: u8) -> SegmentIndex {
        assert!(index <= SEGMENT_INDEX_MAX, "segment index overflow");
        Self(index)
    }
}
#[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Debug, Hash)]
pub struct FCS(u8);

#[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Debug, Hash)]
pub struct MTU(u16);

#[repr(u8)]
#[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Debug, Hash)]
pub enum GPCF {
    TransactionStart = 0b00,
    TransactionAcknowledgment = 0b01,
    TransactionContinuation = 0b10,
    BearerControl = 0b11,
}
impl GPCF {
    pub const fn pack_with(self, six_bits: u8) -> u8 {
        // Mask u8 into a u6.
        let bits = six_bits & 0x3F;
        (bits << 2) | (self as u8)
    }
    pub fn from_masked_u2(u2: u8) -> Self {
        match u2 & 0b11 {
            0b00 => GPCF::TransactionStart,
            0b01 => GPCF::TransactionAcknowledgment,
            0b10 => GPCF::TransactionContinuation,
            0b11 => GPCF::BearerControl,
            _ => unreachable!("only the above 4 GPCF should exist"),
        }
    }
    pub fn unpack_with(byte: u8) -> (Self, u8) {
        (Self::from_masked_u2(byte), (byte & 0xFC) >> 2)
    }
}
impl From<GPCF> for u8 {
    fn from(g: GPCF) -> Self {
        g as u8
    }
}
#[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Debug, Hash, Default)]
pub struct TransactionAcknowledgmentPDU {}
impl TransactionAcknowledgmentPDU {
    pub const BYTE_LEN: usize = ACK_PDU_HEADER_SIZE as usize;
    pub const fn new() -> Self {
        Self {}
    }
    pub const fn as_u8(self) -> u8 {
        GPCF::TransactionAcknowledgment as u8
    }

    pub fn pack_into(self, buf: &mut [u8]) -> Result<(), PackError> {
        PackError::expect_length(Self::BYTE_LEN, buf)?;
        buf[0] = self.as_u8();
        Ok(())
    }
    pub fn unpack_from(buf: &[u8]) -> Result<Self, PackError> {
        PackError::expect_length(Self::BYTE_LEN, buf)?;
        let (gpcf, padding) = GPCF::unpack_with(buf[0]);
        if gpcf != GPCF::TransactionAcknowledgment {
            return Err(PackError::BadOpcode);
        }
        // According to Mesh Core Spec 5.3.1.2, all other values besides 0 are prohibited for padding.
        if padding != 0 {
            return Err(PackError::InvalidFields);
        }
        Ok(Self::new())
    }
    pub const fn is_transaction_ack(b: u8) -> bool {
        Self::new().as_u8() == b
    }
}
impl From<TransactionAcknowledgmentPDU> for u8 {
    fn from(pdu: TransactionAcknowledgmentPDU) -> Self {
        pdu.as_u8()
    }
}
#[derive(Copy, Clone, PartialOrd, PartialEq, Ord, Eq, Debug, Hash)]
pub struct TransactionStartPDU {
    pub seg_n: SegmentIndex,
    pub total_length: u16,
    pub fcs: FCS,
}
/// FCS 3GPP TS 27.010
/// Polynomial x^8 x^2 + x + 1
const FCS_TABLE: [u8; 256] = [
    0x00, 0x91, 0xe3, 0x72, 0x07, 0x96, 0xe4, 0x75, 0x0e, 0x9f, 0xed, 0x7c, 0x09, 0x98, 0xea, 0x7b,
    0x1c, 0x8d, 0xff, 0x6e, 0x1b, 0x8a, 0xf8, 0x69, 0x12, 0x83, 0xf1, 0x60, 0x15, 0x84, 0xf6, 0x67,
    0x38, 0xa9, 0xdb, 0x4a, 0x3f, 0xae, 0xdc, 0x4d, 0x36, 0xa7, 0xd5, 0x44, 0x31, 0xa0, 0xd2, 0x43,
    0x24, 0xb5, 0xc7, 0x56, 0x23, 0xb2, 0xc0, 0x51, 0x2a, 0xbb, 0xc9, 0x58, 0x2d, 0xbc, 0xce, 0x5f,
    0x70, 0xe1, 0x93, 0x02, 0x77, 0xe6, 0x94, 0x05, 0x7e, 0xef, 0x9d, 0x0c, 0x79, 0xe8, 0x9a, 0x0b,
    0x6c, 0xfd, 0x8f, 0x1e, 0x6b, 0xfa, 0x88, 0x19, 0x62, 0xf3, 0x81, 0x10, 0x65, 0xf4, 0x86, 0x17,
    0x48, 0xd9, 0xab, 0x3a, 0x4f, 0xde, 0xac, 0x3d, 0x46, 0xd7, 0xa5, 0x34, 0x41, 0xd0, 0xa2, 0x33,
    0x54, 0xc5, 0xb7, 0x26, 0x53, 0xc2, 0xb0, 0x21, 0x5a, 0xcb, 0xb9, 0x28, 0x5d, 0xcc, 0xbe, 0x2f,
    0xe0, 0x71, 0x03, 0x92, 0xe7, 0x76, 0x04, 0x95, 0xee, 0x7f, 0x0d, 0x9c, 0xe9, 0x78, 0x0a, 0x9b,
    0xfc, 0x6d, 0x1f, 0x8e, 0xfb, 0x6a, 0x18, 0x89, 0xf2, 0x63, 0x11, 0x80, 0xf5, 0x64, 0x16, 0x87,
    0xd8, 0x49, 0x3b, 0xaa, 0xdf, 0x4e, 0x3c, 0xad, 0xd6, 0x47, 0x35, 0xa4, 0xd1, 0x40, 0x32, 0xa3,
    0xc4, 0x55, 0x27, 0xb6, 0xc3, 0x52, 0x20, 0xb1, 0xca, 0x5b, 0x29, 0xb8, 0xcd, 0x5c, 0x2e, 0xbf,
    0x90, 0x01, 0x73, 0xe2, 0x97, 0x06, 0x74, 0xe5, 0x9e, 0x0f, 0x7d, 0xec, 0x99, 0x08, 0x7a, 0xeb,
    0x8c, 0x1d, 0x6f, 0xfe, 0x8b, 0x1a, 0x68, 0xf9, 0x82, 0x13, 0x61, 0xf0, 0x85, 0x14, 0x66, 0xf7,
    0xa8, 0x39, 0x4b, 0xda, 0xaf, 0x3e, 0x4c, 0xdd, 0xa6, 0x37, 0x45, 0xd4, 0xa1, 0x30, 0x42, 0xd3,
    0xb4, 0x25, 0x57, 0xc6, 0xb3, 0x22, 0x50, 0xc1, 0xba, 0x2b, 0x59, 0xc8, 0xbd, 0x2c, 0x5e, 0xcf,
];

pub fn fcs_calc(data: &[u8]) -> FCS {
    let mut fcs = 0xFF;
    for &b in data {
        fcs = FCS_TABLE[usize::from(fcs ^ b)]
    }
    FCS(fcs)
}
pub fn fcs_check(fcs: FCS, data: &[u8]) -> bool {
    let mut fcs_check = 0xFF;
    for &b in data {
        fcs_check = FCS_TABLE[usize::from(fcs_check ^ b)]
    }
    FCS_TABLE[usize::from(fcs_check ^ fcs.0)] == 0xCF
}
const START_PDU_HEADER_SIZE: u16 = 4;
const ACK_PDU_HEADER_SIZE: u16 = 1;
const CONTINUATION_PDU_SIZE: u16 = 1;
impl TransactionStartPDU {
    pub const BYTE_LEN: usize = START_PDU_HEADER_SIZE as usize;
    pub fn calculate_seg_n(data_len: u16, max_mtu: MTU) -> SegmentIndex {
        let mtu = u16::from(max_mtu.0);
        let total_len = data_len + START_PDU_HEADER_SIZE + ACK_PDU_HEADER_SIZE;
        let mut seg_i = total_len / mtu;
        if seg_i * mtu < total_len {
            seg_i += 1;
        }
        SegmentIndex::new(u8::try_from(seg_i).expect("segment index overflow"))
    }
    pub fn new(seg_n: SegmentIndex, length: u16, fcs: FCS) -> Self {
        Self {
            seg_n,
            total_length: length,
            fcs,
        }
    }
    /// Calculates fcs and total length on the `data`. Uses `max_mtu` to calculate `seg_n`.
    /// The returned PDU !DOES NOT! have any data attached to it. Data is contained in the
    /// `Payload` field of `PDU`.
    pub fn from_data(data: &[u8], max_mtu: MTU) -> TransactionStartPDU {
        let data_len = u16::try_from(data.len()).expect("data.len() must fit in a u16");

        Self::new(
            Self::calculate_seg_n(data_len, max_mtu),
            data_len,
            fcs_calc(data),
        )
    }
    pub fn pack_into(self, buf: &mut [u8]) -> Result<(), PackError> {
        PackError::expect_length(Self::BYTE_LEN, buf)?;
        buf[0] = GPCF::TransactionStart.pack_with(self.seg_n.0);
        buf[1..3].copy_from_slice(self.total_length.to_be_bytes().as_ref());
        buf[3] = self.fcs.0;
        Ok(())
    }
    pub fn unpack_from(buf: &[u8]) -> Result<Self, PackError> {
        PackError::expect_length(Self::BYTE_LEN, buf)?;
        let (gpcf, seg_n) = GPCF::unpack_with(buf[0]);
        if gpcf != GPCF::TransactionStart {
            return Err(PackError::BadOpcode);
        }
        let total_len = u16::from_be_bytes((&buf[1..3]).try_into().expect("array checked above"));
        let fcs = buf[3];
        Ok(Self::new(SegmentIndex::new(seg_n), total_len, FCS(fcs)))
    }
}
#[derive(Copy, Clone, PartialOrd, PartialEq, Ord, Eq, Debug, Hash)]
pub struct TransactionContinuationPDU {
    pub seg_i: SegmentIndex,
}
impl TransactionContinuationPDU {
    pub const BYTE_LEN: usize = CONTINUATION_PDU_SIZE as usize;
    pub fn new(seg_i: SegmentIndex) -> Self {
        Self { seg_i }
    }
    pub fn as_u8(self) -> u8 {
        GPCF::TransactionContinuation.pack_with(self.seg_i.0)
    }
    pub fn pack_into(self, buf: &mut [u8]) -> Result<(), PackError> {
        PackError::expect_length(Self::BYTE_LEN, buf)?;
        buf[0] = self.as_u8();
        Ok(())
    }
    pub fn unpack_from(buf: &[u8]) -> Result<Self, PackError> {
        PackError::expect_length(Self::BYTE_LEN, buf)?;
        let (gpcf, seg_i) = GPCF::unpack_with(buf[0]);
        if gpcf != GPCF::TransactionContinuation {
            return Err(PackError::BadOpcode);
        }
        Ok(TransactionContinuationPDU::new(SegmentIndex::new(seg_i)))
    }
}
#[derive(Copy, Clone, PartialOrd, PartialEq, Ord, Eq, Debug, Hash)]
pub enum Control {
    TransactionStart(TransactionStartPDU),
    TransactionContinuation(TransactionContinuationPDU),
    TransactionAcknowledgement(TransactionAcknowledgmentPDU),
    BearerControl(bearer_control::PDU),
}
impl Control {
    pub fn byte_len(&self) -> usize {
        match self {
            Control::TransactionStart(_) => TransactionStartPDU::BYTE_LEN,
            Control::TransactionContinuation(_) => TransactionContinuationPDU::BYTE_LEN,
            Control::TransactionAcknowledgement(_) => TransactionAcknowledgmentPDU::BYTE_LEN,
            Control::BearerControl(pdu) => pdu.byte_len(),
        }
    }
    pub fn pack_into(&self, buf: &mut [u8]) -> Result<(), PackError> {
        match self {
            Control::TransactionStart(p) => p.pack_into(buf),
            Control::TransactionContinuation(p) => p.pack_into(buf),
            Control::TransactionAcknowledgement(p) => p.pack_into(buf),
            Control::BearerControl(p) => p.pack_into(buf),
        }
    }
    pub fn unpack_from(buf: &[u8]) -> Result<Self, PackError> {
        PackError::atleast_length(1, buf)?;
        let (gpcf, _) = GPCF::unpack_with(buf[0]);
        match gpcf {
            GPCF::TransactionStart => Ok(Control::TransactionStart(
                TransactionStartPDU::unpack_from(buf)?,
            )),
            GPCF::TransactionAcknowledgment => Ok(Control::TransactionAcknowledgement(
                TransactionAcknowledgmentPDU::unpack_from(buf)?,
            )),
            GPCF::TransactionContinuation => Ok(Control::TransactionContinuation(
                TransactionContinuationPDU::unpack_from(buf)?,
            )),
            GPCF::BearerControl => Ok(Control::BearerControl(bearer_control::PDU::unpack_from(
                buf,
            )?)),
        }
    }
}
pub const GENERIC_PDU_MAX_LEN: usize = 24;
pub const PAYLOAD_MAX_LEN: usize = 64;
#[derive(Copy, Clone, Eq, PartialEq, Hash, Ord, PartialOrd)]
pub struct PDU<Buf> {
    pub control: Control,
    pub payload: Option<Buf>,
}
impl<Buf: AsRef<[u8]>> PDU<Buf> {
    pub fn byte_len(&self) -> usize {
        self.control.byte_len() + self.payload_len()
    }
    pub fn payload_len(&self) -> usize {
        self.payload.as_ref().map(|l| l.as_ref().len()).unwrap_or(0)
    }
    pub fn pack_into(&self, buf: &mut [u8]) -> Result<(), PackError> {
        let control_len = self.control.byte_len();
        let payload_len = self.payload_len();
        PackError::expect_length(control_len + payload_len, buf)?;
        self.control.pack_into(&mut buf[..control_len])?;
        if let Some(payload) = self.payload.as_ref() {
            if payload_len != 0 {
                buf[control_len..].copy_from_slice(payload.as_ref());
            }
        }
        Ok(())
    }
    pub fn unpack_from(buf: &[u8]) -> Result<Self, PackError>
    where
        Buf: Storage<u8>,
    {
        PackError::atleast_length(1, buf)?;
        let (gpcf, _) = GPCF::unpack_with(buf[0]);
        match gpcf {
            GPCF::TransactionStart => Ok(PDU {
                control: Control::TransactionStart(TransactionStartPDU::unpack_from(
                    &buf[..TransactionStartPDU::BYTE_LEN],
                )?),
                payload: if buf.len() > TransactionStartPDU::BYTE_LEN {
                    Some(Buf::from_slice(&buf[TransactionStartPDU::BYTE_LEN..]))
                } else {
                    None
                },
            }),
            GPCF::TransactionAcknowledgment => Ok(PDU {
                control: Control::TransactionAcknowledgement(
                    TransactionAcknowledgmentPDU::unpack_from(buf)?,
                ),
                payload: None,
            }),
            GPCF::TransactionContinuation => Ok(PDU {
                control: Control::TransactionContinuation(TransactionContinuationPDU::unpack_from(
                    &buf[..TransactionContinuationPDU::BYTE_LEN],
                )?),
                payload: if buf.len() > TransactionContinuationPDU::BYTE_LEN {
                    Some(Buf::from_slice(
                        &buf[TransactionContinuationPDU::BYTE_LEN..],
                    ))
                } else {
                    None
                },
            }),
            GPCF::BearerControl => Ok(PDU {
                control: Control::BearerControl(bearer_control::PDU::unpack_from(buf)?),
                payload: None,
            }),
        }
    }
    pub fn as_ref(&self) -> PDU<&[u8]> {
        PDU {
            control: self.control,
            payload: self.payload.as_ref().map(AsRef::as_ref),
        }
    }
}
impl<T: AsRef<[u8]>> core::fmt::Debug for PDU<T> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("PDU")
            .field("control", &self.control)
            .field("payload", &self.payload.as_ref().map(AsRef::<[u8]>::as_ref))
            .finish()
    }
}
pub const PDU_MTU: u16 = 24;
pub const MAX_START_DATA_LEN: u16 = PDU_MTU - 4;
pub const MAX_CONTINUATION_DATA_LEN: u16 = PDU_MTU - 1;
pub const MAX_PDU_LEN: u16 = PDU_MTU * (SegmentIndex::MAX_SEGMENTS - 1) as u16 + MAX_START_DATA_LEN;
#[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq)]
pub struct SegmentGenerator<B> {
    data: B,
    fcs: FCS,
}
impl<B: AsRef<[u8]>> SegmentGenerator<B> {
    pub fn new(data: B) -> SegmentGenerator<B> {
        assert!(data.as_ref().len() <= usize::from(PDU_MTU));
        SegmentGenerator {
            fcs: fcs_calc(data.as_ref()),
            data,
        }
    }
    /// Number of Segments
    pub fn seg_n(&self) -> SegmentIndex {
        let len = self.data_len();
        if len <= MAX_START_DATA_LEN {
            SegmentIndex::new(0)
        } else {
            SegmentIndex::new(
                ((len + MAX_CONTINUATION_DATA_LEN - 1 - MAX_START_DATA_LEN)
                    / MAX_CONTINUATION_DATA_LEN)
                    .try_into()
                    .expect("segment index overflow"),
            )
        }
    }
    pub fn fcs(&self) -> FCS {
        self.fcs
    }
    pub fn get_segment_data(&self, segment_index: SegmentIndex) -> Option<&'_ [u8]> {
        let seg_n = self.seg_n();
        if segment_index > seg_n {
            None
        } else {
            if segment_index == SegmentIndex::ZERO {
                if segment_index == seg_n {
                    Some(self.data.as_ref())
                } else {
                    Some(&self.data.as_ref()[..MAX_START_DATA_LEN as usize])
                }
            } else {
                let index = usize::from(MAX_START_DATA_LEN)
                    + usize::from(MAX_CONTINUATION_DATA_LEN) * usize::from(segment_index.0 - 1);
                if segment_index == seg_n {
                    Some(&self.data.as_ref()[index..])
                } else {
                    Some(&self.data.as_ref()[index..index + usize::from(MAX_CONTINUATION_DATA_LEN)])
                }
            }
        }
    }
    pub fn data_len(&self) -> u16 {
        // Constructor insures `.len()` fits in an `u16`.
        self.data.as_ref().len() as u16
    }
}
impl<B: AsRef<[u8]>> core::fmt::Debug for SegmentGenerator<B> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("SegmentGenerator<B>")
            .field("data", &self.data.as_ref())
            .field("fcs", &self.fcs)
            .finish()
    }
}
impl<B: AsRef<[u8]>> core::hash::Hash for SegmentGenerator<B> {
    fn hash<H: core::hash::Hasher>(&self, state: &mut H) {
        state.write(self.data.as_ref());
        state.write_u8(self.fcs.0);
    }
}
#[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Debug)]
pub struct Reassembler<B> {
    data: B,
    fcs: FCS,
    seg_i: SegmentIndex,
    seg_n: SegmentIndex,
}
impl<B: AsRef<[u8]>> core::hash::Hash for Reassembler<B> {
    fn hash<H: core::hash::Hasher>(&self, state: &mut H) {
        state.write(self.data.as_ref());
        state.write_u8(self.fcs.0);
        state.write_u8(self.seg_i.0);
        state.write_u8(self.seg_n.0);
    }
}
#[derive(Copy, PartialOrd, PartialEq, Ord, Eq, Hash, Debug, Clone)]
pub enum ReassembleError {
    NotFinished,
    TooManySegments,
    SegmentRepeat,
    SegmentSkipped,
    DataUnderflow,
    DataOverflow,
    FCSMismatch,
    PackError(PackError),
}
impl<B: AsRef<[u8]> + AsMut<[u8]>> Reassembler<B> {
    pub fn new_started(
        data: B,
        fcs: FCS,
        seg_n: SegmentIndex,
        seg_i: SegmentIndex,
    ) -> Reassembler<B> {
        assert!(
            data.as_ref().len() < (u16::MAX as usize),
            "data.len() overflows a u16"
        );
        Reassembler {
            data,
            fcs,
            seg_i,
            seg_n,
        }
    }
    pub fn new(data: B, fcs: FCS, seg_n: SegmentIndex) -> Reassembler<B> {
        Self::new_started(data, fcs, seg_n, SegmentIndex::ZERO)
    }
    pub fn from_start(
        start: TransactionStartPDU,
        data: &[u8],
    ) -> Result<Reassembler<B>, ReassembleError>
    where
        B: Storage<u8>,
    {
        let mut out = Self::new(
            B::with_size(start.total_length.into()),
            start.fcs,
            start.seg_n,
        );
        debug_assert_eq!(out.total_len(), start.total_length);
        out.insert(data, SegmentIndex(0))?;
        Ok(out)
    }
    pub fn total_len(&self) -> u16 {
        // Trim usize -> u16 on purpose. Both are checked in constructor to not overflow u16
        self.data.as_ref().len() as u16
    }
    pub fn fcs(&self) -> FCS {
        self.fcs
    }
    pub fn fcs_finished(&self) -> Option<FCS> {
        if self.is_done() {
            Some(fcs_calc(self.all_data()))
        } else {
            None
        }
    }
    pub fn seg_n(&self) -> SegmentIndex {
        self.seg_i
    }
    pub fn seg_i(&self) -> SegmentIndex {
        self.seg_i
    }
    pub fn data_index(&self) -> u16 {
        match self.seg_i {
            SegmentIndex(0) => 0,
            SegmentIndex(1) => MAX_START_DATA_LEN,
            SegmentIndex(i) => MAX_CONTINUATION_DATA_LEN * u16::from(i - 1) + MAX_START_DATA_LEN,
        }
    }
    pub fn is_done(&self) -> bool {
        debug_assert!(self.seg_i <= self.seg_n, "seg_i overflow");
        self.seg_i == self.seg_n
    }
    pub fn current_data(&self) -> &[u8] {
        &self.data.as_ref()[..self.data_index() as usize]
    }
    pub fn all_data(&self) -> &[u8] {
        self.data.as_ref()
    }
    pub fn fcs_matches(&self) -> Option<bool> {
        if self.is_done() {
            Some(fcs_check(self.fcs, self.data.as_ref()))
        } else {
            None
        }
    }
    pub fn into_inner(self) -> B {
        self.data
    }
    pub fn finish_data(self) -> Result<B, ReassembleError> {
        if self.fcs_matches().ok_or(ReassembleError::NotFinished)? {
            Ok(self.data)
        } else {
            Err(ReassembleError::FCSMismatch)
        }
    }
    pub fn finish_data_ref(&self) -> Result<&[u8], ReassembleError> {
        if self.fcs_matches().ok_or(ReassembleError::NotFinished)? {
            Ok(self.data.as_ref())
        } else {
            Err(ReassembleError::FCSMismatch)
        }
    }
    pub fn finish_pdu(&self) -> Result<protocol::PDU, ReassembleError> {
        let data = self.finish_data_ref()?;
        protocol::PDU::unpack_raw(data.as_ref()).map_err(ReassembleError::PackError)
    }
    pub fn insert(
        &mut self,
        segment_data: &[u8],
        seg_i: SegmentIndex,
    ) -> Result<(), ReassembleError> {
        if self.seg_n >= seg_i {
            return Err(ReassembleError::TooManySegments);
        }
        if self.seg_i > seg_i {
            return Err(ReassembleError::SegmentRepeat);
        }
        if self.seg_i < seg_i {
            return Err(ReassembleError::SegmentSkipped);
        }
        if self.seg_i == SegmentIndex::ZERO {
            if segment_data.len() > usize::from(MAX_START_DATA_LEN) {
                return Err(ReassembleError::DataOverflow);
            }
            if self.seg_n != SegmentIndex(1) && segment_data.len() < usize::from(MAX_START_DATA_LEN)
            {
                return Err(ReassembleError::DataUnderflow);
            }
            if segment_data.len() < self.data.as_ref().len() {
                return Err(ReassembleError::DataUnderflow);
            }
            self.data.as_mut()[..usize::from(MAX_START_DATA_LEN)]
                .copy_from_slice(segment_data.as_ref());
        } else {
            if segment_data.len() > usize::from(MAX_CONTINUATION_DATA_LEN) {
                return Err(ReassembleError::DataOverflow);
            }
            if self.seg_n != seg_i && segment_data.len() < usize::from(MAX_CONTINUATION_DATA_LEN) {
                return Err(ReassembleError::DataUnderflow);
            }
            let index = usize::from(MAX_START_DATA_LEN)
                + usize::from(seg_i.0) * usize::from(MAX_CONTINUATION_DATA_LEN);
            if index + segment_data.len() < self.data.as_ref().len() {
                return Err(ReassembleError::DataUnderflow);
            }
            self.data.as_mut()[index..index + usize::from(MAX_CONTINUATION_DATA_LEN)]
                .copy_from_slice(segment_data.as_ref());
        }
        self.seg_i = seg_i;
        Ok(())
    }
}
