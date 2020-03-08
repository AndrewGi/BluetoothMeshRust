use slog::Drain;
#[macro_use]
extern crate slog;

use std::convert::TryFrom;

pub mod commands;
pub mod helper;
pub enum CLIError {
    PermissionDenied,
    IOError(String, std::io::Error),
    Clap(clap::Error),
    SerdeJSON(serde_json::Error),
    OtherMessage(String),
    Other(Box<dyn std::error::Error>),
}

fn main() {
    let app = clap::App::new("Bluetooth Mesh CLI")
        .version(clap::crate_version!())
        .author("Andrew Gilbrough <andrew@gilbrough.com>")
        .about("Bluetooth Mesh Command Line Interface tool to interact with the Mesh")
        .arg(
            clap::Arg::with_name("verbose")
                .short("v")
                .long("verbose")
                .multiple(true)
                .max_values(5)
                .help("Set the amount of logging from level 0 up to level 5"),
        )
        .arg(
            clap::Arg::with_name("device_state")
                .short("s")
                .long("device_state")
                .value_name("FILE")
                .help("Specifies device state .json file"),
        )
        .subcommand(commands::state::sub_command())
        .subcommand(commands::provisioner::sub_command())
        .subcommand(commands::crypto::sub_command())
        .subcommand(commands::ble::sub_command());
    let matches = app.get_matches();

    let _log_level = slog::Level::from_usize(
        1 + usize::try_from(matches.occurrences_of("verbose"))
            .expect("verbose usize overflow (how??)"),
    )
    .expect("verbose limit set too low");
    let drain = slog_term::PlainSyncDecorator::new(std::io::stdout());
    let root = slog::Logger::root(slog_term::FullFormat::new(drain).build().fuse(), slog::o!());
    /*
    let root = slog::LevelFilter::new(
        slog::Logger::root(slog_term::FullFormat::new(drain).build().fuse(), slog::o!()),
        log_level,
    );
    */
    trace!(root, "main");
    let sub_cmd = matches.subcommand().0;
    let get_device_state_path = || -> &str {
        match matches.value_of("device_state") {
            Some(path) => path,
            None => clap::Error::with_description(
                "missing 'device_state.json` path",
                clap::ErrorKind::ArgumentNotFound,
            )
            .exit(),
        }
    };
    debug!(root, "arg_match"; "sub_command" => sub_cmd);
    if let Err(e) = (|| -> Result<(), CLIError> {
        match matches.subcommand() {
            ("", None) => error!(root, "no command given"),
            ("state", Some(gen_matches)) => {
                commands::state::state_matches(&root, get_device_state_path(), gen_matches)?
            }
            ("crypto", Some(crypto_matches)) => {
                commands::crypto::crypto_matches(&root, get_device_state_path(), crypto_matches)?
            }
            ("provisioner", Some(prov_matches)) => commands::provisioner::provisioner_matches(
                &root,
                get_device_state_path(),
                prov_matches,
            )?,
            ("ble", Some(ble_matches)) => commands::ble::ble_matches(&root, ble_matches)?,
            _ => unreachable!("unhandled sub_command"),
        }
        debug!(root, "matches_done");
        Ok(())
    })() {
        match e {
            CLIError::IOError(path, error) => {
                eprintln!("io error {:?} with path '{}'", error, path)
            }
            CLIError::Clap(error) => eprintln!("{}", &error.message),
            CLIError::SerdeJSON(error) => eprintln!("json error {}", error),
            CLIError::PermissionDenied => {
                eprintln!("permission denied error! (are you running as sudo/admin)?")
            }
            CLIError::OtherMessage(msg) => eprintln!("error: {}", &msg),
            CLIError::Other(e) => eprintln!("error: {}", e)
        };
        std::process::exit(0);
    }
    ()
}
