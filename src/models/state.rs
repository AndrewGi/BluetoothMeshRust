use crate::access::Opcode;
use crate::models::{MessagePackError, PackableMessage};

pub trait State {}

pub trait StateEndpoint {
    type Message: PackableMessage;
    fn opcode() -> Opcode;
    fn handle_message(&mut self, message: Self::Message);
    fn handle_message_bytes(&mut self, bytes: &[u8]) -> Result<(), MessagePackError> {
        let msg = Self::Message::unpack_from(bytes)?;
        self.handle_message(msg);
        Ok(())
    }
}
