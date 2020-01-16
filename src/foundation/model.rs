use crate::access::ModelIdentifier;
use crate::foundation::publication::ModelPublishInfo;

#[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug)]
pub struct ModelComposition {
    pub model_identifier: ModelIdentifier,
    pub publish_info: ModelPublishInfo,
}
impl ModelComposition {
    pub fn is_sig(&self) -> bool {
        self.model_identifier.is_sig()
    }
    pub fn is_vendor(&self) -> bool {
        self.model_identifier.is_vendor()
    }
}
