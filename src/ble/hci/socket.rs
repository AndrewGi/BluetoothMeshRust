#[derive(Copy, Debug)]
#[repr(C)]
struct SockaddrHCI {
    hci_family: libc::sa_family_t,
    hci_dev: u16,
    hci_channel: u16,
}
pub struct HCISocket {
    fd: i32,
}
pub fn handle_libc_error(i: i32) -> Result<i32, HCISocketError> {
    if i < 0 {
        Err(nix::errno::Errno)
    }
}
pub enum HCISocketError {
    PermissionDenied,
    DeviceNotFound,
    NotConnected,
    Other(i32),
}
impl HCISocket {
    pub fn new() -> Result<HCISocket, HCISocketError> {
        let adapter_fd = handle_libc_error(unsafe {
            libc::socket(libc::AF_BLUETOOTH, libc::SOCK_RAW | libc::SOCK_CLOEXEC, 1)
        })?;
    }
}
