use crate::helper;
use crate::CLIError;
use btle::error::IOError;
use btle::le::report::ReportInfo;
use futures_util::StreamExt;
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
        ("", _) => dump(adapter_id, &logger).map_err(CLIError::Other),
        _ => unreachable!("unhandled subcommand"),
    }
}
pub fn dump(_: u16, _: &slog::Logger) -> Result<(), Box<dyn std::error::Error>> {
    let mut runtime = tokio::runtime::Builder::new()
        .enable_all()
        .build()
        .expect("can't make async runtime");
    runtime.block_on(async move {
        #[cfg(unix)]
        return dump_bluez(
            std::env::args()
                .skip(1)
                .next()
                .unwrap_or("0".to_owned())
                .parse()
                .expect("invalid adapter id"),
        )
        .await;
        return Ok(dump_usb().await?);
    })
}

pub fn dump_not_supported() -> Result<(), Box<dyn std::error::Error>> {
    eprintln!("no known support adapter for this platform. (When this example was written)");
    Ok(())
}
#[cfg(unix)]
pub fn dump_bluez(adapter_id: u16) -> Result<(), Box<dyn std::error::Error>> {
    use btle::error::StdError;
    let manager = btle::hci::socket::Manager::new().map_err(StdError)?;
    let socket = match manager.get_adapter_socket(btle::hci::socket::AdapterID(adapter_id)) {
        Ok(socket) => socket,
        Err(btle::hci::socket::HCISocketError::PermissionDenied) => {
            eprintln!("Permission denied error when opening the HCI socket. Maybe run as sudo?");
            return Err(btle::hci::socket::HCISocketError::PermissionDenied)
                .map_err(StdError)
                .map_err(Into::into);
        }
        Err(e) => return Err(StdError(e).into()),
    };

    let async_socket = btle::hci::socket::AsyncHCISocket::try_from(socket)?;
    let stream = btle::hci::stream::Stream::new(async_socket);
    let adapter = btle::hci::adapters::Adapter::new(stream);
    dump_adapter(adapter)
        .await
        .map_err(|e| Box::new(btle::error::StdError(e)))?;
    Result::<(), Box<dyn std::error::Error>>::Ok(())
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
    use std::convert::TryFrom;
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
pub async fn dump_usb() -> Result<(), btle::hci::adapter::Error> {
    use btle::hci::usb;
    let context = usb::manager::Manager::new()?;
    println!("opening first device...");
    let device: usb::device::Device = context
        .devices()?
        .bluetooth_adapters()
        .next()
        .ok_or(IOError::NotFound)??;
    println!("using {:?}", device);
    let mut adapter = device.open()?;
    adapter.reset()?;
    dump_adapter(adapter).await
}
pub async fn dump_adapter<A: btle::hci::adapter::Adapter>(
    mut adapter: A,
) -> Result<(), btle::hci::adapter::Error> {
    let adapter = unsafe { Pin::new_unchecked(&mut adapter) };
    let adapter = btle::hci::adapters::Adapter::new(adapter);
    let mut le = adapter.le();
    println!("resetting adapter...");
    le.adapter_mut().reset().await?;
    println!("settings scan parameters...");
    // Set BLE Scan parameters (when to scan, how long, etc)
    le.set_scan_parameters(btle::le::scan::ScanParameters::DEFAULT)
        .await?;
    // Enable scanning for advertisement packets.
    le.set_scan_enable(true, false).await?;

    println!("waiting for advertisements...");
    // Create the advertisement stream from the LEAdapter.
    let mut stream = le.advertisement_stream::<Box<[ReportInfo]>>().await?;
    // Pin it.
    let mut stream = unsafe { Pin::new_unchecked(&mut stream) };
    loop {
        // Asynchronously iterate through the stream and print each advertisement report.
        while let Some(report) = stream.next().await {
            println!("report: {:?}", &report);
        }
    }
}
