// Generalized over the rand Library so there's no hard dependencies.

pub fn rand_bool() -> bool {
    rand::random()
}

pub fn rand_u8() -> u8 {
    rand::random()
}

pub fn rand_u16() -> u16 {
    rand::random()
}

pub fn rand_u32() -> u32 {
    rand::random()
}

pub fn rand_u64() -> u64 {
    rand::random()
}

pub fn rand_16_bytes() -> [u8; 16] {
    rand::random()
}

pub fn rand_32_bytes() -> [u8; 32] {
    rand::random()
}
