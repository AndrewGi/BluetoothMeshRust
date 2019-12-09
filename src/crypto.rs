
pub struct NetKeyIndex(u16);
pub struct AppKeyIndex(u16);

pub struct Key {
    bytes: [u8; 16]
}
pub struct NetKey(Key);
pub struct AppKey(Key);