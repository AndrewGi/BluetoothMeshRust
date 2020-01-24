use crate::CLIError;

pub fn sub_command() -> clap::App<'static, 'static> {
    clap::SubCommand::with_name("provisioner")
        .about("Provisioner Role for adding Nodes to a network")
}
pub fn provisioner_matches(logger: &slog::Logger, device_state_path: &str, matches: &clap::ArgMatches) -> Result<(), CLIError> {
    unimplemented!()
}