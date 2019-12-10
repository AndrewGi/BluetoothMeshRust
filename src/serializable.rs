use crate::bytes::{Buf, BufMut, Bytes, BytesMut};

pub enum SerializableError {
    OutOfSpace,
    BadBytes,
    IncorrectSize,
    IncorrectParameter,
    Other,
}

pub trait WireSerializable: Sized {
    ///
    /// This trait is for objects/structures that will be Serialized to be sent over the Wire.
    /// Explain: PDUs, statuses, message, etc
    /// Things like Address may seem to be WireSerializable but the byteorder depends on which
    /// place in the stack the Address is.
    ///
    type Error;
    fn serialize_to<'a>(&self, buf: &'a mut BytesMut<'a>) -> Result<(), Self::Error>;
    fn serialize_from<'a>(buf: &'a mut Bytes<'a>) -> Result<Self, Self::Error>;
}
