use crate::ble::hci::{Command, ErrorCode, EventPacket, HCICommandError, HCIConversionError};
use core::convert::TryFrom;

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
impl From<PacketType> for u32 {
    fn from(packet_type: PacketType) -> Self {
        packet_type as u32
    }
}
impl TryFrom<u8> for PacketType {
    type Error = HCIConversionError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0x01 => Ok(PacketType::Command),
            0x02 => Ok(PacketType::ACLData),
            0x03 => Ok(PacketType::SCOData),
            0x04 => Ok(PacketType::Event),
            0xFF => Ok(PacketType::Vendor),
            _ => Err(HCIConversionError(())),
        }
    }
}
pub enum StreamError {
    CommandError(HCICommandError),
    IOError,
    HCIError(ErrorCode),
}
/// HCI Stream Sink that consumes any HCI Events or Status.
pub trait StreamSink {
    fn consume_event(&self, event: EventPacket<&[u8]>);
}
/// Generic HCI Stream. Abstracted to HCI Command/Event Packets. If you only have access to a
/// HCI Byte Stream, see [`byte_stream::ByteStream`] instead.
pub trait Stream<Sink: StreamSink> {
    /// Take a reader sink and start any reader tasks/threads
    fn take_sink(&mut self, sink: Sink);
    /// Send a HCI Command to the Controller. Responses will be sent to the sink.
    fn send_command<Cmd: Command>(&mut self, command: &Cmd) -> Result<(), StreamError>;
}
/// Optionally ByteStream abstraction but depends on `std` for `std::io::Write`, `std::io::read`
/// and `std::thread::spawn`.
#[cfg(std)]
pub mod byte_stream {
    use super::{Stream, StreamSink};
    use crate::ble::hci::stream::StreamError;
    use crate::ble::hci::Command;
    use alloc::sync::Arc;
    use alloc::vec::Vec;
    use core::ops::Deref;
    use std::io::{Read, Write};

    /// Generic HCI Byte Stream according to HCI Spec. Usually used with [`socket::HCISocket`] but
    /// could also be used with a UART driver, TLS socket, etc.
    pub struct ByteStream<Sink: StreamSink + Send, S: Write + Read + Clone + Send> {
        stream: S,
    }
    impl<Sink: StreamSink + Sen, S: Write + Read + Clone + Send> ByteStream<Sink, S> {
        /// Wraps a stream with support for [`stream::Stream`]. This is not free because a thread
        /// is spawned when the sink is taken.
        pub fn new(stream: S) -> Self {
            Self { stream }
        }
        fn start_read_thread(&self, sink: Sink) {
            let mut reader = self.stream.clone();
            std::thread::spawn(move || {
                let mut buf = Vec::new();
                let mut reader_buf = [0_u8; 512];
                loop {
                    let amount = match reader.read(&mut reader_buf[..]) {
                        Ok(amount) => {
                            if amount != 0 {
                                buf.extend_from_slice(&reader_buf[..amount]);
                            } else {
                                continue;
                            }
                            amount
                        }
                        Err(_) => {
                            // Reader err, close the stream
                            return;
                        }
                    };
                    if amount == reader_buf.len() {
                        // Still more left to read in the buffer
                        continue;
                    }
                    todo!("process event/status")
                }
            });
        }
    }
    impl<Sink: StreamSink, S: Write + Read> Stream<Sink> for ByteStream<Sink, S> {
        fn take_sink(&mut self, sink: Sink) {
            self.start_read_thread(sink)
        }

        fn send_command<Cmd: Command>(&mut self, command: &Cmd) -> Result<(), StreamError> {
            // OGF + OCF + LEN = 3 extra bytes
            let mut buf = [0_u8; 0xFF + 3];
            let l = command.byte_len();
            command
                .pack_full(&mut buf[..l + 3])
                .map_err(StreamError::CommandError)?;
            self.stream
                .write(&buf[..l + 3])
                .ok()
                .ok_or(StreamError::IOError)?;
            self.stream.flush();
            // TODO: Get Response
            Ok(())
        }
    }
}
