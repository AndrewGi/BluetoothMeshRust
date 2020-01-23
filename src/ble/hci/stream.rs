use crate::ble::hci::{CommandPacket, ErrorCode, EventPacket};

#[derive(Copy, Clone, PartialOrd, PartialEq, Ord, Eq, Hash, Debug)]
#[repr(u8)]
pub enum PacketType {
    Command = 0x01,
    ACLData = 0x02,
    SCOData = 0x03,
    Event = 0x04,
    Vendor = 0xFF,
}
impl From<PacketType> for u8 {
    fn from(packet_type: PacketType) -> Self {
        packet_type as u8
    }
}
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
