use crate::helper::tokio_runtime;
use crate::CLIError;
use bluetooth_mesh::provisioning::link::Link;
use bluetooth_mesh::provisioning::pb_adv;
use bluetooth_mesh::random::Randomizable;
use bluetooth_mesh::replay;
use bluetooth_mesh::stack::bearer::{IncomingMessage, OutgoingMessage, PBAdvBuf};
use bluetooth_mesh::stack::bearers::advertiser::BufferedHCIAdvertiser;
use bluetooth_mesh::stack::full::FullStack;
use bluetooth_mesh::stack::StackInternals;
use bluetooth_mesh::uuid::UUID;
use driver_async::asyncs::sync::mpsc;
use driver_async::asyncs::task;
use futures_util::stream::{Stream, StreamExt};
pub fn sub_command() -> clap::App<'static, 'static> {
    clap::SubCommand::with_name("provisioner")
        .about("Provisioner Role for adding Nodes to a network")
        .subcommand(
            clap::SubCommand::with_name("run")
                .about("join real Bluetooth Mesh network as a provisioner.")
                .arg(
                    clap::Arg::with_name("source")
                        .help("HCI source/sink (`bluez`/`usb`)")
                        .short("s")
                        .long("source")
                        .value_name("SOURCE_NAME:ADAPTER_ID")
                        .default_value("usb:0"),
                ),
        )
}
pub fn provisioner_matches(
    logger: &slog::Logger,
    device_state_path: &str,
    matches: &clap::ArgMatches,
) -> Result<(), CLIError> {
    let mut runtime = tokio_runtime();
    match matches.subcommand() {
        ("run", Some(run_matches)) => tokio::task::LocalSet::new().block_on(
            &mut runtime,
            provision(
                logger,
                run_matches.value_of("source").expect("required by clap"),
                device_state_path,
            ),
        ),
        ("", None) => Err(CLIError::Clap(clap::Error::with_description(
            "missing subcommand",
            clap::ErrorKind::ArgumentNotFound,
        ))),
        _ => unreachable!("unhandled provisioner subcommand"),
    }
}
async fn filter_only_pb_adv<
    S: Stream<Item = Result<IncomingMessage, btle::hci::adapter::Error>> + Unpin,
>(
    mut stream: S,
) -> Result<Option<pb_adv::IncomingPDU<PBAdvBuf>>, btle::hci::adapter::Error> {
    while let Some(msg) = stream.next().await {
        if let Some(pb_adv_pdu) = msg?.pb_adv() {
            return Ok(Some(pb_adv_pdu));
        }
    }
    Ok(None)
}
pub async fn dump() -> Result<(), CLIError> {
    unimplemented!()
}
pub async fn provision(
    _logger: &slog::Logger,
    which_adapter: &'_ str,
    device_state_path: &str,
) -> Result<(), CLIError> {
    const BEARER_CHANNEL_SIZE: usize = 16;
    let dsm = crate::helper::load_device_state(device_state_path)?;
    println!("opening HCI adapter...");
    let adapter = crate::helper::hci_adapter(which_adapter).await?;
    println!("HCI adapter (`{:?}`) open!", adapter);
    // TODO: I wrote a async usb driver (`usbw`) so a BufferedHCIAdvertiser might not be needed anymore!
    let (mut adapter, mut bearer_rx, bearer_tx) =
        BufferedHCIAdvertiser::new_with_channel_size(adapter, BEARER_CHANNEL_SIZE);
    let _adapter_task = task::spawn(async move {
        adapter.run_loop_send_error().await;
    });
    async move {
        let early_end_error =
            || CLIError::OtherMessage("early end on incoming advertisement stream".to_owned());
        println!("starting buffered advertiser...");
        let internals = StackInternals::new(dsm);
        let cache = replay::Cache::new();
        let stack = FullStack::new(internals, cache, 5);
        // Box<[u8]> stores the PDU being assembled for the pb-adv link.
        println!("waiting for beacons...");
        let beacon = loop {
            if let Some(beacon) = bearer_rx.recv().await.ok_or(early_end_error())??.beacon() {
                if beacon.beacon.unprovisioned().is_some() {
                    break beacon;
                }
            }
        };
        println!("using beacon: `{:?}`", &beacon);
        let uuid: UUID = beacon.beacon.unprovisioned().expect("filtered above").uuid;
        println!("UUID: {}", &uuid);
        let (tx_link, mut rx_link) = mpsc::channel(Link::<Box<[u8]>>::CHANNEL_SIZE);
        let mut bearer_link_tx = bearer_tx.clone();
        // Forwards PB ADV Link messages to the bearer
        task::spawn(async move {
            while let Some(msg) = rx_link.recv().await {
                dbg!(&msg);
                if bearer_link_tx
                    .send(OutgoingMessage::PBAdv(msg))
                    .await
                    .is_err()
                {
                    return;
                }
            }
        });

        let mut link = Link::<PBAdvBuf>::invite(tx_link, pb_adv::LinkID::random(), &uuid);
        let next_pb_adv = move || async move {
            Result::<_, Box<dyn btle::error::Error>>::Ok(
                filter_only_pb_adv(&mut bearer_rx)
                    .await?
                    .ok_or_else(early_end_error)?
                    .pdu,
            )
        };
        link.handle_pb_adv_pdu(next_pb_adv().await?.as_ref())
            .await?;
        println!("{:?}", link.state());
        Result::<(), Box<dyn btle::error::Error>>::Ok(())
    }
    .await
    .map_err(|e| CLIError::OtherMessage(format!("stack error: {:?}", e)))?;
    println!("provisioner done");
    Ok(())
}
