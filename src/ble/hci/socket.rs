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
#[derive(Copy, Clone, PartialOrd, PartialEq, Ord, Eq, Hash, Debug)]
#[repr(u16)]
enum HCIChannel {
    Raw = 0,
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
pub struct HCISocket {
    socket: UnixStream,
}
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
    Other(i32),
}
impl HCISocket {
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
        Ok(HCISocket {
            socket: unsafe { UnixStream::from_raw_fd(adapter_fd) },
        })
    }
}
