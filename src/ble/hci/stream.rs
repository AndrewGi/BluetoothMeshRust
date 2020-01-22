use crate::ble::hci::{CommandPacket, ErrorCode, EventPacket};

pub enum StreamError {
    HCIError(ErrorCode),
}
pub trait StreamSink {
    fn consume_event(&self, event: EventPacket<&[u8]>);
}
pub trait Stream<'sink> {
    fn take_sink(&'sink mut self, sink: &'sink dyn StreamSink);
    fn send_command(&self, command: CommandPacket<&[u8]>) -> Result<(), StreamError>;
}
