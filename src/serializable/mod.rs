pub mod bytes;

pub trait ByteSerializable: Sized {
    ///
    /// This trait is for objects/structures that will be Serialized to be sent over the Air/Wire.
    /// Explain: PDUs, statuses, message, etc
    /// Things like Address may seem to be WireSerializable but the byteorder depends on which
    /// place in the stack the Address is. (Ex: Network Layer BIG Endian Address, Access Layer Little Endian).
    ///
    /// For things depending on byte order, use bytes.rs ToFromByteEndian
    ///

    fn serialize_to(&self, buf: &mut bytes::BytesMut) -> Result<(), bytes::BufError>;
    fn serialize_from(buf: &mut bytes::Bytes) -> Result<Self, bytes::BufError>;
}

//pub mod byte_derive;
#[cfg(test)]
pub mod tests;
