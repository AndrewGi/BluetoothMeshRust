use crate::CLIError;

pub mod adapters;
pub mod dump;
pub mod pcap;
pub fn sub_command() -> clap::App<'static, 'static> {
    clap::SubCommand::with_name("hci")
        .about("interact with Bluetooth HCI (Host Controller Interface)")
        .subcommand(dump::sub_command())
        .subcommand(adapters::sub_command())
}

pub fn hci_matches(
    parent_logger: &slog::Logger,
    ble_matches: &clap::ArgMatches,
) -> Result<(), CLIError> {
    let subcommand_str = ble_matches.subcommand_name().unwrap_or("");
    let logger = parent_logger.new(o!("sub_command" => subcommand_str.to_owned()));
    debug!(logger, "hci_matches");
    match ble_matches.subcommand() {
        ("dump", Some(dump_matches)) => dump::dump_matches(&logger, dump_matches),
        ("adapters", _) => adapters::list_possible_adapters(),
        _ => Err(CLIError::Clap(clap::Error::with_description(
            "missing sub_command",
            clap::ErrorKind::ArgumentNotFound,
        ))),
    }
}
