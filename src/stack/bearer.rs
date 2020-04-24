//! Bluetooth Mesh Bearers.
use crate::mesh::TransmitInterval;
use crate::provisioning::pb_adv;
use crate::{beacon, net};
use btle::le::advertisement::{AdType, OutgoingAdvertisement};
use btle::le::report::{EventType, ReportInfo};
use btle::RSSI;
use futures_util::stream::{Stream, StreamExt};

#[derive(Debug)]
pub enum BearerError {
    Other(Box<dyn btle::error::Error + Send + 'static>),
}

#[derive(Copy, Clone)]
pub struct IncomingEncryptedNetworkPDU {
    pub encrypted_pdu: net::OwnedEncryptedPDU,
    pub rssi: Option<RSSI>,
    pub dont_relay: bool,
}
impl IncomingEncryptedNetworkPDU {
    pub fn from_report_info(report_info: ReportInfo<&[u8]>) -> Option<IncomingEncryptedNetworkPDU> {
        if report_info.event_type == EventType::AdvInd {
            if let Some(ad_struct) = report_info.data.iter().next() {
                if ad_struct.ad_type == AdType::MeshPDU {
                    return Some(IncomingEncryptedNetworkPDU {
                        encrypted_pdu: net::OwnedEncryptedPDU::new(ad_struct.buf.as_ref())?,
                        rssi: report_info.rssi,
                        dont_relay: false,
                    });
                }
            }
        }
        None
    }
}

#[derive(Copy, Clone)]
pub struct OutgoingEncryptedNetworkPDU {
    pub transmit_parameters: TransmitInterval,
    pub pdu: net::OwnedEncryptedPDU,
}
pub struct IncomingBeacon {
    pub beacon: beacon::BeaconPDU,
    pub rssi: Option<RSSI>,
}
pub enum OutgoingMessage {
    Network(OutgoingEncryptedNetworkPDU),
}
impl From<&OutgoingMessage> for OutgoingAdvertisement {
    fn from(_: &OutgoingMessage) -> Self {
        todo!("implement outgoing messages")
    }
}
impl From<OutgoingMessage> for OutgoingAdvertisement {
    fn from(o: OutgoingMessage) -> Self {
        (&o).into()
    }
}
pub enum IncomingMessage {
    Network(IncomingEncryptedNetworkPDU),
    Beacon(IncomingBeacon),
    PBAdv(pb_adv::IncomingPDU),
}
impl IncomingMessage {
    pub fn from_report_info_stream<In: Stream<Item = Result<ReportInfo, BearerError>>>(
        in_stream: In,
    ) -> impl Stream<Item = Result<IncomingMessage, BearerError>> {
        in_stream.filter_map(|r| async move {
            match r {
                Ok(report_info) => {
                    if report_info.event_type == EventType::AdvInd {
                        if let Some(ad_struct) = report_info.data.iter().next() {
                            match ad_struct.ad_type {
                                AdType::MeshPDU => Some(Ok(IncomingMessage::Network(
                                    IncomingEncryptedNetworkPDU {
                                        encrypted_pdu: net::OwnedEncryptedPDU::new(
                                            ad_struct.buf.as_ref(),
                                        )?,
                                        rssi: report_info.rssi,
                                        dont_relay: false,
                                    },
                                ))),
                                AdType::MeshBeacon => {
                                    Some(Ok(IncomingMessage::Beacon(IncomingBeacon {
                                        beacon: beacon::BeaconPDU::unpack_from(
                                            ad_struct.buf.as_ref(),
                                        )
                                        .ok()?,
                                        rssi: report_info.rssi,
                                    })))
                                }
                                AdType::PbAdv => {
                                    Some(Ok(IncomingMessage::PBAdv(pb_adv::IncomingPDU {
                                        pdu: pb_adv::PDU::unpack_from(ad_struct.buf.as_ref())
                                            .ok()?,
                                        rssi: report_info.rssi,
                                    })))
                                }
                                _ => None,
                            }
                        } else {
                            None
                        }
                    } else {
                        None
                    }
                }
                Err(e) => Some(Err(e)),
            }
        })
    }
}
