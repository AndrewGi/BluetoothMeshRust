use crate::access::Opcode;
use crate::foundation::publication::ModelPublishInfo;
use crate::models::state::StateEndpoint;

pub trait Model {}

pub struct ModelInfo {
    publish: ModelPublishInfo,
}
