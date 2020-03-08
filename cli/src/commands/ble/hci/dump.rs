use crate::helper;
use crate::CLIError;
use std::pin::Pin;

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
        .arg(
            clap::Arg::with_name("adapter_id")
                .help("specify the HCI adapter ID")
                .short("a")
                .long("adapter_id")
                .default_value("0")
                .value_name("ADAPTER_ID")
                .validator(helper::is_u16_validator),
        )
}

pub fn dump_matches(
    parent_logger: &slog::Logger,
    dump_matches: &clap::ArgMatches,
) -> Result<(), CLIError> {
    let logger = parent_logger.new(o!());
    info!(logger, "dump");
    let adapter_id: u16 = dump_matches
        .value_of("adapter_id")
        .expect("has default value")
        .parse()
        .expect("validated by clap");
    match dump_matches.subcommand() {
        ("", _) => dump_bluez(adapter_id, &logger),
        _ => unreachable!("unhandled subcommand"),
    }
}
#[cfg(not(unix))]
pub fn dump_bluez(_: u16, _: &slog::Logger) -> Result<(), CLIError> {
    Err(CLIError::OtherMessage(
        "bluez only supported on unix systems".to_owned(),
    ))
}
#[cfg(unix)]
pub fn dump_bluez(adapter_id: u16, parent_logger: &slog::Logger) -> Result<(), CLIError> {
    use btle::hci::socket;
    use core::convert::TryFrom;
    let map_hci_socket_err = |err: socket::HCISocketError| match err {
        socket::HCISocketError::BadData => CLIError::OtherMessage("hci socket bad data".to_owned()),
        socket::HCISocketError::PermissionDenied => CLIError::PermissionDenied,
        socket::HCISocketError::IO(io) => CLIError::IOError("hci socket IO error".to_owned(), io),
        socket::HCISocketError::DeviceNotFound => {
            CLIError::OtherMessage("hci socket device not found".to_owned())
        }
        socket::HCISocketError::NotConnected => {
            CLIError::OtherMessage("hci socket not connected".to_owned())
        }
        socket::HCISocketError::Busy => CLIError::OtherMessage("hci device busy".to_owned()),
        socket::HCISocketError::Other(errno) => {
            CLIError::OtherMessage(format!("hci socket errno error `{}`", errno))
        }
        socket::HCISocketError::Unsupported => {
            CLIError::OtherMessage("hci supported error".to_owned())
        }
    };
    let logger = parent_logger.new(o!("adapter_id" => adapter_id));
    debug!(logger, "dump_bluez");
    info!(logger, "opening manager...");
    let manager = socket::Manager::new().map_err(map_hci_socket_err)?;
    info!(logger, "opening hci socket...");
    let socket = manager
        .get_adapter_socket(socket::AdapterID(adapter_id))
        .map_err(map_hci_socket_err)?;
    info!(logger, "opened socket");
    let mut runtime = tokio::runtime::Builder::new()
        .enable_all()
        .build()
        .expect("can't make async runtime");

    runtime.block_on(async move {
        let async_socket = socket::AsyncHCISocket::try_from(socket)
            .map_err(|e| map_hci_socket_err(socket::HCISocketError::IO(e)))?;
        let stream = btle::hci::stream::Stream::new(async_socket);
        let adapter = btle::hci::adapters::Adapter::new(stream);
        dump_adapter(adapter, &logger)
            .await
            .map_err(|e| CLIError::Other(Box::new(btle::error::STDError(e))))
    })
}
pub async fn dump_adapter<S: btle::hci::stream::HCIStreamable>(
    mut adapter: btle::hci::adapters::Adapter<S, Box<[u8]>>,
    logger: &slog::Logger,
) -> Result<(), btle::hci::adapters::Error> {
    let mut adapter = unsafe { Pin::new_unchecked(&mut adapter) };
    info!(logger, "scan_command");
    adapter.as_mut().le().set_scan_enabled(true, false).await?;
    info!(logger, "scan_enabled");
    loop {
        let _next = adapter.as_mut().read_event().await?;
        println!("got something");
    }
}
