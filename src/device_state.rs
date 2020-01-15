//! Device State Manager used to storing device state and having an config client control it.
use crate::crypto::materials::SecurityMaterials;
use crate::mesh::{IVIndex, IVUpdateFlag, IVI};

pub struct State {
    iv_update_flag: IVUpdateFlag,
    iv_index: IVIndex,
    security_materials: SecurityMaterials,
}
impl State {
    /// IVIndex used for transmitting.
    pub fn tx_iv_index(&self) -> IVIndex {
        self.iv_index
    }
    /// IVIndex used for receiving. Will return `None` if no matching `IVIndex` can be found.
    /// See [`IVIndex::matching_flags`] for more.
    pub fn rx_iv_index(&self, ivi: IVI) -> Option<IVIndex> {
        self.iv_index.matching_flags(ivi, self.iv_update_flag)
    }
    pub fn iv_index(&self) -> IVIndex {
        self.iv_index
    }
    pub fn security_materials(&self) -> &SecurityMaterials {
        &self.security_materials
    }
}
