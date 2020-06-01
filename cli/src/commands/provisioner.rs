use crate::helper::tokio_runtime;
use crate::CLIError;
use bluetooth_mesh::provisioning::link::Link;
use bluetooth_mesh::provisioning::pb_adv;
use bluetooth_mesh::random::Randomizable;
use bluetooth_mesh::replay;
use bluetooth_mesh::stack::bearer::{IncomingMessage, PBAdvBuf};
use bluetooth_mesh::stack::full::FullStack;
use bluetooth_mesh::stack::StackInternals;
use bluetooth_mesh::uuid::UUID;
use btle::le::advertisement::StaticAdvBuffer;
use btle::le::report::ReportInfo;
use driver_async::asyncs::sync::mpsc;
use futures_util::stream::{Stream, StreamExt};

pub fn sub_command() -> clap::App<'static, 'static> {
    clap::SubCommand::with_name("provisioner")
        .about("Provisioner Role for adding Nodes to a network")
        .subcommand(
            clap::SubCommand::with_name("run")
                .about("join real Bluetooth Mesh network as a provisioner."),
        )
}
pub fn provisioner_matches(
    logger: &slog::Logger,
    device_state_path: &str,
    matches: &clap::ArgMatches,
) -> Result<(), CLIError> {
    match matches.subcommand() {
        ("run", Some(_matches)) => tokio_runtime().block_on(provision(logger, device_state_path)),
        ("", None) => Err(CLIError::Clap(clap::Error::with_description(
            "missing subcommand",
            clap::ErrorKind::ArgumentNotFound,
        ))),
        _ => unreachable!("unhandled provisioner subcommand"),
    }
}
fn incoming_stream(
    s: impl Stream<Item = Result<ReportInfo<StaticAdvBuffer>, btle::hci::adapter::Error>>,
) -> impl Stream<Item = Result<IncomingMessage, btle::hci::adapter::Error>> {
    s.filter_map(|r| async move {
        r.map(|i| IncomingMessage::from_report_info(i.as_ref()))
            .transpose()
    })
}
async fn filter_only_pb_adv<
    S: Stream<Item = Result<IncomingMessage, btle::hci::adapter::Error>>,
>(
    mut stream: core::pin::Pin<&mut S>,
) -> Result<Option<pb_adv::IncomingPDU<PBAdvBuf>>, btle::hci::adapter::Error> {
    while let Some(incoming_result) = stream.as_mut().next().await {
        if let Some(pb_adv_pdu) = incoming_result?.pb_adv() {
            return Ok(Some(pb_adv_pdu));
        }
    }
    Ok(None)
}
pub async fn dump() -> Result<(), CLIError> {
    unimplemented!()
}
pub async fn provision(_logger: &slog::Logger, device_state_path: &str) -> Result<(), CLIError> {
    let dsm = crate::helper::load_device_state(device_state_path)?;
    println!("opening usb adapter...");
    let adapter = crate::helper::usb_adapter(0)?;
    println!("usb adapter open!");
    let adapter = btle::hci::adapters::Adapter::new(adapter);
    let mut le = adapter.le();
    async move {
        let early_end_error =
            || CLIError::OtherMessage("early end on incoming advertisement stream".to_owned());
        let mut incoming = incoming_stream(le.advertisement_stream::<Box<[ReportInfo]>>().await?);
        //Intellij doesn't like pin_mut!
        //futures_util::pin_mut!(incoming);
        let mut incoming = unsafe { core::pin::Pin::new_unchecked(&mut incoming) };
        let internals = StackInternals::new(dsm);
        let cache = replay::Cache::new();
        let stack = FullStack::new(internals, cache, 5);
        // Box<[u8]> stores the PDU being assembled for the pb-adv link.
        println!("waiting for beacons...");
        let beacon = loop {
            if let Some(beacon) = incoming.next().await.ok_or(early_end_error())??.beacon() {
                dbg!(beacon);
                if beacon.beacon.unprovisioned().is_some() {
                    break beacon;
                }
            }
        };
        println!("using beacon: `{:?}`", &beacon);
        let uuid: UUID = beacon.beacon.unprovisioned().expect("filtered above").uuid;
        println!("UUID: {}", &uuid);
        let (tx_link, rx_link) = mpsc::channel(Link::<Box<[u8]>>::CHANNEL_SIZE);
        let mut link = Link::<Box<[u8]>>::invite(tx_link, pb_adv::LinkID::random(), &uuid);
        let mut incoming_borrow = incoming.as_mut();
        let next_pb_adv = move || async move {
            Result::<_, Box<dyn btle::error::Error>>::Ok(
                filter_only_pb_adv(incoming_borrow.as_mut())
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
