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

/// An Access Message that can be packed into a (little endian) byte buffer.
/// If a message comes in that matches `Opcode`, the stack will try to decode it with
/// `PackableMessage::unpack_from`.
pub trait PackableMessage: Sized {
    fn opcode() -> Opcode;
    /// Bytes need to fit the entire message in bytes (excluding opcode).
    fn message_size(&self) -> usize;
    /// Pack the message into the byte buffer (without the opcode). If the length of the buffer is
    /// too small or the object is in a bad state, return `MessagePackError`.
    fn pack_into(&self, buffer: &mut [u8]) -> Result<(), MessagePackError>;
    fn pack_with_opcode(&self, buffer: &mut [u8]) -> Result<(), MessagePackError> {
        let opcode = Self::opcode();
        let opcode_len = opcode.byte_len();
        self.pack_into(&mut buffer[opcode_len..opcode_len + self.message_size()])?;
        opcode
            .pack_into(&mut buffer[..opcode_len])
            .expect("incorrectly formatted opcode");
        Ok(())
    }
    /// Unpack the message from the byte buffer (without the opcode). Make sure to check for a valid
    /// message or return a `MessagePackError` otherwise.
    fn unpack_from(buffer: &[u8]) -> Result<Self, MessagePackError>;
}
