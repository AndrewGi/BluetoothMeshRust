use crate::ble::hci::stream::{PacketType, StreamError, StreamSink};
use crate::ble::hci::{stream, Command, CommandPacket, EventCode};
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, Ordering};
use std::os::unix::{
    io::{FromRawFd, RawFd},
    net::UnixStream,
};

#[repr(i32)]
enum BTProtocol {
    L2CAP = 0,
    HCI = 1,
    SCO = 2,
    RFCOMM = 3,
    BNEP = 4,
    CMTP = 5,
    HIDP = 6,
    AVDTP = 7,
}
impl From<BTProtocol> for i32 {
    fn from(protocol: BTProtocol) -> Self {
        protocol as i32
    }
}
/// BlueZ HCI Channels. Each Channel gives different levels of control over the Bluetooth
/// Controller.
#[derive(Copy, Clone, PartialOrd, PartialEq, Ord, Eq, Hash, Debug)]
#[repr(u16)]
enum HCIChannel {
    /// Requires sudo. Exclusive access to the Controller.
    Raw = 0,
    /// Shouldn't require sudo. Exclusive access to the Controller.
    User = 1,
    Monitor = 2,
    Control = 3,
}
impl From<HCIChannel> for u16 {
    fn from(channel: HCIChannel) -> Self {
        channel as u16
    }
}
#[derive(Copy, Clone, Debug)]
#[repr(C)]
struct SockaddrHCI {
    hci_family: libc::sa_family_t,
    hci_dev: u16,
    hci_channel: u16,
}
/// Wrapper for a BlueZ HCI Stream. Uses Unix Sockets. `HCISocket`'s have a special filter on them
/// for HCI Events so that is why they are wrapped. Besides the filter, they are just byte streams
/// that need to have the Events and Commands abstracted over them.
pub struct HCISocket {
    socket: UnixStream,
}
/// Turns an libc `ERRNO` error number into a `HCISocketError`.
pub fn handle_libc_error(i: RawFd) -> Result<i32, HCISocketError> {
    if i < 0 {
        Err(HCISocketError::Other(nix::errno::errno()))
    } else {
        Ok(i)
    }
}
pub enum HCISocketError {
    PermissionDenied,
    DeviceNotFound,
    NotConnected,
    IO(std::io::Error),
    Other(i32),
}
impl HCISocket {
    /// Creates an `HCISocket` based on a `libc` file_descriptor (`i32`). Returns an error if could
    /// not bind to the `adapter_id`.
    pub fn new(adapter_id: u16) -> Result<HCISocket, HCISocketError> {
        let adapter_fd = handle_libc_error(unsafe {
            libc::socket(
                libc::AF_BLUETOOTH,
                libc::SOCK_RAW | libc::SOCK_CLOEXEC,
                BTProtocol::HCI.into(),
            )
        })?;
        let address = SockaddrHCI {
            hci_family: libc::AF_BLUETOOTH as u16,
            hci_dev: adapter_id,
            hci_channel: HCIChannel::User.into(),
        };
        handle_libc_error(unsafe {
            libc::bind(
                adapter_fd,
                &address as *const SockaddrHCI as *const libc::sockaddr,
                std::mem::size_of::<SockaddrHCI>() as u32,
            )
        })?;
        let is_running = Arc::new(AtomicBool::new(true));
        let socket = unsafe { UnixStream::from_raw_fd(adapter_fd) };
        let out = HCISocket {
            socket: socket.try_clone()?,
        };
        out.set_filter();
        Ok(out)
    }
}
impl HCISocket {
    /// Sets the HCI Event filter on the socket. Should only need to be called once. Is also called
    /// automatically by the `new` constructor.
    pub fn set_filter(&self) -> Result<(), HCISocketError> {
        const HCI_FILTER: i32 = 2;
        const SOL_HCI: i32 = 0;
        let type_mask =
            (1u32 << u32::from(PacketType::Command)) | (1u32 << u32::from(PacketType::Event));
        let event_mask1 = (1u32 << u32::from(EventCode::CommandComplete))
            | (1u32 << u32::from(EventCode::CommandStatus));

        let mut filter = [0_u8; 14];
        filter[0..4].copy_from_slice(&type_mask.to_bytes_le());
        filter[4..8].copy_from_slice(&event_mask1.to_bytes_le());

        handle_libc_error(unsafe {
            libc::setsockopt(
                self.socket.as_raw_fd(),
                SOL_HCI,
                HCI_FILTER,
                filter.as_mut_ptr() as *mut _ as *mut libc::c_void,
                filter.len() as u32,
            )
        })?;
        Ok(())
    }
}
use std::io::Error;
impl std::io::Write for HCISocket {
    fn write(&mut self, buf: &[u8]) -> Result<usize, Error> {
        self.socket.write(buf)
    }

    fn flush(&mut self) -> Result<(), Error> {
        self.socket.flush()
    }
}
impl std::io::Read for HCISocket {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize, Error> {
        self.socket.read(buf)
    }
}
