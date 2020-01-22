use crate::provisioning::pb_adv;
use crate::provisioning::pb_adv::{LinkID, TransactionNumber};

pub struct Links {}

pub enum LinkError {
    Closed,
}

pub struct Link {
    link_id: LinkID,
    my_transaction_number: TransactionNumber,
    other_transaction_number: Option<TransactionNumber>,
}
impl Link {
    pub fn handle_pb_adv_pdu(&mut self, pdu: &pb_adv::PDU) {
        if pdu.link_id != self.link_id {
            return;
        }
    }
}
