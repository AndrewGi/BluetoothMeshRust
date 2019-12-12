use crate::bytes::{Buf, BufMut, Bytes, BytesMut};

pub enum ByteSerializableError {
    OutOfSpace,
    BadBytes,
    IncorrectSize,
    IncorrectParameter,
    Other,
}

pub trait ByteSerializable: Sized {
    ///
    /// This trait is for objects/structures that will be Serialized to be sent over the Air/Wire.
    /// Explain: PDUs, statuses, message, etc
    /// Things like Address may seem to be WireSerializable but the byteorder depends on which
    /// place in the stack the Address is. (Ex: Network Layer BIG Endian Address, Access Layer Little Endian).
    ///
    /// For things depending on byte order, use bytes.rs ToFromByteEndian
    ///
    type Error;

    fn serialize_to(&self, buf: &mut BytesMut) -> Result<(), Self::Error>;
    fn serialize_from(buf: &mut Bytes) -> Result<Self, Self::Error>;
}
