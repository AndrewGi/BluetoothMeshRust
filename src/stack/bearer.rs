//! Bluetooth Mesh Bearers.
use crate::mesh::{TransmitCount, TransmitInterval, TransmitSteps};
use crate::provisioning::{link, pb_adv};
use crate::{beacon, net};
use btle::bytes::StaticBuf;
use btle::le::advertisement::{AdType, RawAdvertisement};
use btle::le::report::{EventType, ReportInfo};
use btle::{PackError, RSSI};

#[derive(Debug)]
pub enum BearerError {
    Other(Box<dyn btle::error::Error + Send + 'static>),
}

#[derive(Copy, Clone, Debug, Eq, PartialEq, Hash, Ord, PartialOrd)]
pub struct IncomingEncryptedNetworkPDU {
    pub encrypted_pdu: net::EncryptedPDU<net::StaticEncryptedPDUBuf>,
    pub rssi: Option<RSSI>,
    pub dont_relay: bool,
}
impl IncomingEncryptedNetworkPDU {
    pub fn from_report_info(report_info: ReportInfo<&[u8]>) -> Option<IncomingEncryptedNetworkPDU> {
        if report_info.event_type == EventType::AdvInd {
            if let Some(ad_struct) = report_info.data.iter().next() {
                if ad_struct.ad_type == AdType::MeshPDU {
                    return Some(IncomingEncryptedNetworkPDU {
                        encrypted_pdu: net::EncryptedPDU::new(ad_struct.buf.as_ref())?.to_owned(),
                        rssi: report_info.rssi,
                        dont_relay: false,
                    });
                }
            }
        }
        None
    }
}

#[derive(Copy, Clone, Debug, Eq, PartialEq, Hash, Ord, PartialOrd)]
pub struct OutgoingEncryptedNetworkPDU {
    pub transmit_parameters: TransmitInterval,
    pub pdu: net::EncryptedPDU<net::StaticEncryptedPDUBuf>,
}
#[derive(Copy, Clone, Debug, Eq, PartialEq, Hash, Ord, PartialOrd)]
pub struct IncomingBeacon {
    pub beacon: beacon::BeaconPDU,
    pub rssi: Option<RSSI>,
}
pub type PBAdvBuf = StaticBuf<u8, [u8; link::GENERIC_PDU_DATA_MAX_LEN]>;
#[derive(Copy, Clone, Debug, Eq, PartialEq, Hash, Ord, PartialOrd)]
pub enum OutgoingMessage {
    Network(OutgoingEncryptedNetworkPDU),
    Beacon(beacon::BeaconPDU),
    PBAdv(pb_adv::PDU<PBAdvBuf>),
}
impl OutgoingMessage {
    pub fn to_raw_advertisement(&self) -> Result<(RawAdvertisement, TransmitInterval), PackError> {
        let mut out = RawAdvertisement::new();
        Ok(match self {
            OutgoingMessage::Network(n) => {
                out.insert(&n.pdu)?;
                (out, n.transmit_parameters)
            }
            OutgoingMessage::Beacon(b) => {
                out.insert(b)?;
                (
                    out,
                    TransmitInterval::new(TransmitCount::new(3), TransmitSteps::new(2)),
                )
            }
            OutgoingMessage::PBAdv(p) => {
                out.insert(p)?;
                (
                    out,
                    TransmitInterval::new(TransmitCount::new(3), TransmitSteps::new(1)),
                )
            }
        })
    }
}
#[derive(Copy, Clone, Debug, Eq, PartialEq, Hash, Ord, PartialOrd)]
pub enum IncomingMessage {
    Network(IncomingEncryptedNetworkPDU),
    Beacon(IncomingBeacon),
    PBAdv(pb_adv::IncomingPDU<PBAdvBuf>),
}
impl IncomingMessage {
    pub fn from_report_info<B: AsRef<[u8]>>(report_info: ReportInfo<B>) -> Option<IncomingMessage> {
        if report_info.event_type == EventType::AdvNonconnInd {
            if let Some(ad_struct) = report_info.data.iter().next() {
                dbg!(ad_struct.ad_type);
                match ad_struct.ad_type {
                    AdType::MeshPDU => {
                        Some(IncomingMessage::Network(IncomingEncryptedNetworkPDU {
                            encrypted_pdu: net::EncryptedPDU::new(ad_struct.buf.as_ref())?
                                .to_owned(),
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
    pub fn network_pdu(&self) -> Option<IncomingEncryptedNetworkPDU> {
        match self {
            IncomingMessage::Network(n) => Some(*n),
            _ => None,
        }
    }
    pub fn beacon(&self) -> Option<IncomingBeacon> {
        match self {
            IncomingMessage::Beacon(b) => Some(*b),
            _ => None,
        }
    }
    pub fn pb_adv(
        &self,
    ) -> Option<pb_adv::IncomingPDU<StaticBuf<u8, [u8; link::GENERIC_PDU_DATA_MAX_LEN]>>> {
        match self {
            IncomingMessage::PBAdv(p) => Some(*p),
            _ => None,
        }
    }
}
/// ['IncomingMessage`] or [`OutgoingMessage`]
#[derive(Copy, Clone, Debug, Eq, PartialEq, Hash, Ord, PartialOrd)]
pub enum Message {
    Outgoing(OutgoingMessage),
    Incoming(IncomingMessage),
}
impl From<OutgoingMessage> for Message {
    fn from(m: OutgoingMessage) -> Self {
        Message::Outgoing(m)
    }
}
impl From<IncomingMessage> for Message {
    fn from(m: IncomingMessage) -> Self {
        Message::Incoming(m)
    }
}
/*
pub fn single_shot_advertisement<A: btle::hci::adapter::Adapter, B: AsRef<[u8]>>(
    le: &mut btle::hci::adapters::le::LEAdapter<A>,
    advertisement: OutgoingAdvertisement,
) -> Result<(), btle::hci::adapter::Error> {
    le.set_advertising_data()
}
*/
#[cfg(test)]
mod tests {
    use crate::beacon::BeaconPDU::Unprovisioned;
    use crate::beacon::{OOBInformation, URIHash, UnprovisionedDeviceBeacon};
    use crate::stack::bearer::IncomingBeacon;
    use crate::stack::bearer::IncomingMessage;
    use crate::stack::bearer::IncomingMessage::Beacon;
    use crate::uuid::UUID;
    use btle::le::advertisement::RawAdvertisement;
    use btle::le::report::AddressType::RandomDevice;
    use btle::le::report::EventType::AdvNonconnInd;
    use btle::le::report::ReportInfo;
    use btle::{BTAddress, RSSI};

    #[test]
    pub fn test_beacon() {
        assert_eq!(
            IncomingMessage::from_report_info(ReportInfo {
                event_type: AdvNonconnInd,
                address_type: RandomDevice,
                address: BTAddress([7, 63, 215, 62, 99, 46,],),
                rssi: Some(RSSI::new(-60,),),
                data: RawAdvertisement(&[
                    24, 43, 0, 221, 221, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 32, 0, 0, 0,
                    0,
                ]),
            })
            .unwrap(),
            Beacon(IncomingBeacon {
                beacon: Unprovisioned(UnprovisionedDeviceBeacon {
                    uuid: UUID([221, 221, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,],),
                    oob_information: OOBInformation(32,),
                    uri_hash: Some(URIHash(0,),),
                },),
                rssi: Some(RSSI::new(-60,),),
            },)
        );
    }
}
