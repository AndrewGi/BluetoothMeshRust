use crate::access::Opcode;

pub mod config;
pub mod generics;
pub mod lighting;
pub mod sensors;
pub mod state;
pub mod time;

/// Error when trying to pack a message into a byte buffer.
pub enum MessagePackError {
    /// Byte Buffer too small to fit the whole message.
    SmallBuffer,
    /// Incoming Byte Buffer length doesn't make sense.
    BadLength,
    /// Incoming Byte Buffer creates an invalid message.
    BadBytes,
    /// Message can't be packed because the object is in a bad state.
    BadState,
}

pub trait PackableMessage {
    fn opcode() -> Opcode;
    /// Bytes need to fit the entire message in bytes (excluding opcode).
    fn message_size(&self) -> usize;
    fn pack_into(&self, buffer: &mut [u8]) -> Result<(), MessagePackError>;
    fn unpack_from(buffer: &[u8]) -> Result<Self, MessagePackError>;
}
