use crate::crypto::materials::SecurityMaterials;
use crate::mesh::IVIndex;

pub struct State {
    iv_index: IVIndex,
    security_materials: SecurityMaterials,
}
impl State {
    pub fn iv_index(&self) -> IVIndex {
        self.iv_index
    }
    pub fn security_materials(&self) -> &SecurityMaterials {
        &self.security_materials
    }
}
