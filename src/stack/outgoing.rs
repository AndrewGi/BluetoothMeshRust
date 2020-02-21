use crate::stack::messages::{OutgoingMessage, OutgoingUpperTransportMessage};
use crate::stack::{SendError, StackInternals};
use std::sync::Arc;
use tokio::sync::RwLock;

pub struct Outgoing {}
pub struct AppEncrypter(pub Arc<RwLock<StackInternals>>);
impl AppEncrypter {
    pub fn app_encrypt<Storage: AsRef<[u8]> + AsMut<[u8]>>(
        &self,
        msg: OutgoingMessage<Storage>,
    ) -> Result<OutgoingUpperTransportMessage<Storage>, (SendError, OutgoingMessage<Storage>)> {
        unimplemented!();
    }
}
impl Outgoing {
    pub fn new() {}
}
