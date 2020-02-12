use crate::CLIError;
use btle::hci::stream::{HCIReader, HCIWriter};

pub fn sub_command() -> clap::App<'static, 'static> {
    clap::SubCommand::with_name("dump")
        .about("dump raw HCI data to the console")
        .arg(
            clap::Arg::with_name("decode")
                .help("decode the HCI Event Packets into their respective objects")
                .short("s")
                .long("decode")
                .takes_value(false),
        )
}

pub fn dump_matches(
    parent_logger: &slog::Logger,
    dump_matches: &clap::ArgMatches,
) -> Result<(), CLIError> {
    let logger = parent_logger.new(o!());
    info!(logger, "dump");
    match dump_matches.subcommand() {
        ("", _) => dump_bluez(0, &logger),
        _ => unreachable!("unhandled subcommand"),
    }
}
#[cfg(not(unix))]
pub fn dump_bluez(_: u16, _: &slog::Logger) -> Result<(), CLIError> {
    Err(CLIError::Other(
        "bluez only supported on unix systems".to_owned(),
    ))
}
#[cfg(unix)]
pub fn dump_bluez(adapter_id: u16, parent_logger: &slog::Logger) -> Result<(), CLIError> {
    use btle::hci::le::SetScanEnable;
    use btle::hci::socket;
    use core::convert::TryFrom;
    let map_hci_socket_err = |err: socket::HCISocketError| match err {
        socket::HCISocketError::BadData => CLIError::Other("hci socket bad data".to_owned()),
        socket::HCISocketError::PermissionDenied => CLIError::PermissionDenied,
        socket::HCISocketError::IO(io) => CLIError::IOError("hci socket IO error".to_owned(), io),
        socket::HCISocketError::DeviceNotFound => {
            CLIError::Other("hci socket device not found".to_owned())
        }
        socket::HCISocketError::NotConnected => {
            CLIError::Other("hci socket not connected".to_owned())
        }
        socket::HCISocketError::Busy => CLIError::Other("hci device busy".to_owned()),
        socket::HCISocketError::Other(errno) => {
            CLIError::Other(format!("hci socket errno error `{}`", errno))
        }
        socket::HCISocketError::Unsupported => CLIError::Other("hci supported error".to_owned()),
    };
    let logger = parent_logger.new(o!("adapter_id" => adapter_id));
    debug!(logger, "dump_bluez");
    info!(logger, "opening manager...");
    let manager = socket::Manager::new().map_err(map_hci_socket_err)?;
    info!(logger, "opening hci socket...");
    let socket = manager
        .get_adapter_socket(socket::AdapterID(0))
        .map_err(map_hci_socket_err)?;
    info!(logger, "opened socket");
    let mut runtime = tokio::runtime::Builder::new()
        .enable_all()
        .build()
        .expect("can't make async runtime");
    info!(logger, "starting async loop");
    runtime.block_on(async move {
        use futures::StreamExt;
        let mut async_socket = socket::AsyncHCISocket::try_from(socket)
            .map_err(|e| map_hci_socket_err(socket::HCISocketError::IO(e)))?;
        let mut stream = btle::hci::stream::ByteStream::new(&mut async_socket);
        stream
            .send_command(SetScanEnable {
                is_enabled: false,
                filter_duplicates: false,
            })
            .expect("correctly formatted command")
            .await
            .expect("io_error");
        info!(logger, "sent_enable");
        loop {
            let next = stream.read_event().await;
            println!("got something");
        }
        Ok(())
    })
}
