//! Bluetooth Mesh Bearers.
use crate::mesh::TransmitInterval;
use crate::provisioning::pb_adv;
use crate::{beacon, net};
use btle::le::advertisement::{AdType, OutgoingAdvertisement};
use btle::le::report::{EventType, ReportInfo};
use btle::RSSI;

#[derive(Debug)]
pub enum BearerError {
    Other(Box<dyn btle::error::Error + Send + 'static>),
}

#[derive(Copy, Clone, Debug)]
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

#[derive(Copy, Clone, Debug)]
pub struct OutgoingEncryptedNetworkPDU {
    pub transmit_parameters: TransmitInterval,
    pub pdu: net::OwnedEncryptedPDU,
}
#[derive(Copy, Clone, Debug)]
pub struct IncomingBeacon {
    pub beacon: beacon::BeaconPDU,
    pub rssi: Option<RSSI>,
}
#[derive(Debug)]
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
#[derive(Debug)]
pub enum IncomingMessage {
    Network(IncomingEncryptedNetworkPDU),
    Beacon(IncomingBeacon),
    PBAdv(pb_adv::IncomingPDU),
}
impl IncomingMessage {
    pub fn from_report_info(report_info: ReportInfo) -> Option<IncomingMessage> {
        if report_info.event_type == EventType::AdvNonconnInd {
            dbg!(&report_info);
            if let Some(ad_struct) = report_info.data.iter().next() {
                dbg!(ad_struct.ad_type);
                match ad_struct.ad_type {
                    AdType::MeshPDU => {
                        Some(IncomingMessage::Network(IncomingEncryptedNetworkPDU {
                            encrypted_pdu: net::OwnedEncryptedPDU::new(ad_struct.buf.as_ref())?,
                            rssi: report_info.rssi,
                            dont_relay: false,
                        }))
                    }
                    AdType::MeshBeacon => Some(IncomingMessage::Beacon(IncomingBeacon {
                        beacon: beacon::BeaconPDU::unpack_from(ad_struct.buf.as_ref()).ok()?,
                        rssi: report_info.rssi,
                    })),
                    AdType::PbAdv => Some(IncomingMessage::PBAdv(pb_adv::IncomingPDU {
                        pdu: pb_adv::PDU::unpack_from(ad_struct.buf.as_ref()).ok()?,
                        rssi: report_info.rssi,
                    })),
                    _ => None,
                }
            } else {
                None
            }
        } else {
            None
        }
    }
}
