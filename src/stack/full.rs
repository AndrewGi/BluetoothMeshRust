use crate::stack::StackInternals;
use std::sync::mpsc;

pub struct FullStack {
	network_pdu_channel: mpsc::Receiver<>
    internals: StackInternals,
}
