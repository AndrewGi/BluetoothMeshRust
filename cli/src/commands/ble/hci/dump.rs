use crate::helper;
use crate::CLIError;
use btle::le::report::ReportInfo;
use futures_util::StreamExt;
use std::pin::Pin;

pub fn sub_command() -> clap::App<'static, 'static> {
    clap::SubCommand::with_name("dump")
        .about("dump raw HCI data to the console")
        .arg(
            clap::Arg::with_name("source")
                .help("HCI source/sink (`bluez`/`usb`)")
                .short("s")
                .long("source")
                .value_name("SOURCE_NAME")
                .default_value("usb"),
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
        .arg(
            clap::Arg::with_name("pcap")
                .help("dump the BLE advertisements to a pcap file/pipe")
                .short("p")
                .long("pcap")
                .value_name("PCAP_FILE"),
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
    let pcap_file = dump_matches.value_of("pcap");
    let source = dump_matches.value_of("source").expect("required by clap");
    match dump_matches.subcommand() {
        ("", _) => dump(&logger, source, adapter_id, pcap_file),
        _ => unreachable!("unhandled subcommand"),
    }
}
pub fn dump(
    _: &slog::Logger,
    source: &'_ str,
    adapter_id: u16,
    pcap_file: Option<&'_ str>,
) -> Result<(), CLIError> {
    crate::helper::tokio_runtime().block_on(async move {
        match source {
            "usb" => dump_adapter_pcap(helper::usb_adapter(adapter_id)?, pcap_file).await,
            "bluez" => dump_adapter_pcap(helper::bluez_adapter(adapter_id)?, pcap_file).await,
            _ => Err(CLIError::OtherMessage(format!(
                "HCI source `{}` unknown",
                source
            ))),
        }
    })
}
pub async fn dump_adapter_pcap<A: btle::hci::adapter::Adapter>(
    adapter: A,
    pcap_file: Option<&'_ str>,
) -> Result<(), CLIError> {
    match pcap_file {
        Some(pcap_file) => {
            println!("using pcap file '{}'", pcap_file);
            dump_adapter(super::pcap::PcapAdapter::open(adapter, pcap_file)?).await
        }
        None => dump_adapter(adapter).await,
    }
}
pub async fn dump_adapter<A: btle::hci::adapter::Adapter>(adapter: A) -> Result<(), CLIError> {
    let adapter = btle::hci::adapters::Adapter::new(adapter);
    let mut le = adapter.le();
    println!("resetting adapter...");
    le.adapter.reset().await?;
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
