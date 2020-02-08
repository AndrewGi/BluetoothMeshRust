use crate::CLIError;

pub fn sub_command() -> clap::App<'static, 'static> {
    clap::SubCommand::with_name("provisioner")
        .about("Provisioner Role for adding Nodes to a network")
}
pub fn provisioner_matches(_logger: &slog::Logger, _device_state_path: &str, _matches: &clap::ArgMatches) -> Result<(), CLIError> {
    unimplemented!()
}