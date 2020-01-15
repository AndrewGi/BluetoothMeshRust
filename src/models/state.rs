use crate::access::Opcode;

pub trait State {}

pub trait StatusState: State {
    type StatusType;
    fn status_opcode() -> Opcode;
    fn status(&self) -> Self::StatusType;
}
pub trait GetState: State {}
