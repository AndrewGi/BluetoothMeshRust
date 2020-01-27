use crate::CLIError;
use bluetooth_mesh::device_state;
use std::convert::TryFrom;
use std::fmt::{Error, Formatter};
use std::str::FromStr;
use std::num::ParseIntError;

pub struct HexSlice<'a>(pub &'a [u8]);
impl<'a> std::fmt::UpperHex for HexSlice<'a> {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), Error> {
        for &b in self.0 {
            write!(f, "{:X}", b)?;
        }
        Ok(())
    }
}

impl<'a> std::fmt::LowerHex for HexSlice<'a> {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), Error> {
        for &b in self.0 {
            write!(f, "{:02x}", b)?;
        }
        Ok(())
    }
}
pub fn is_hex_str(s: &str) -> bool {
    if s.len() % 2 == 1 {
        return false;
    }
    for c in s.chars() {
        if !c.is_digit(16) {
            return false;
        }
    }
    return true;
}
pub fn is_128_bit_hex_str_validator(input: String) -> Result<(), String> {
    if input.len() == 32 && is_hex_str(&input) {
        Ok(())
    } else {
        Err(format!("'{}' is not a 128-bit hex string", &input))
    }
}
pub fn is_u24_validator(input: String) -> Result<(), String> {
    match u32::from_str(&input).ok().and_then(|v| bluetooth_mesh::mesh::U24::try_from(v).ok()) {
        Some(_) => Ok(()),
        None => Err(format!("'{}' is not a 24-unsigned integer", &input))
    }
}
pub fn is_u32_validator(input: String) -> Result<(), String> {
    match u32::from_str(&input) {
        Ok(_) => Ok(()),
        Err(_) => Err(format!("'{}' is not a 32-unsigned integer", &input))
    }
}
pub fn hex_str_to_bytes<T: Default + AsMut<[u8]>>(s: &str) -> Option<T> {
    let mut out = T::default();
    if s.len() != out.as_mut().len() * 2 || out.as_mut().len() == 0 {
        None
    } else {
        {
            let buf = out.as_mut();
            for (i, c) in s.chars().enumerate() {
                let v = u8::try_from(c.to_digit(16)?).expect("only returns [0..=15]");
                buf[i / 2] |= v << u8::try_from(((i + 1) % 2) * 4).expect("only returns 0 or 4");
            }
        }
        Some(out)
    }
}
pub fn is_bool_validator(input: String) -> Result<(), String> {
    bool::from_str(&input).ok().map(|_|()).ok_or(format!("'{}' is not a valid bool", &input))
}
pub fn load_file(path: &str, writeable: bool, create: bool) -> Result<std::fs::File, CLIError> {
    std::fs::OpenOptions::new()
        .read(true)
        .write(writeable)
        .truncate(true)
        .create(create)
        .open(path)
        .map_err(|e| CLIError::IOError(path.to_owned(), e))
}
pub fn load_device_state(path: &str) -> Result<device_state::DeviceState, CLIError> {
    serde_json::from_reader(load_file(path, false, false)?).map_err(CLIError::SerdeJSON)
}
pub fn write_device_state(
    path: &str,
    device_state: &device_state::DeviceState,
) -> Result<(), CLIError> {
    serde_json::to_writer(load_file(path, true, true)?, device_state).map_err(CLIError::SerdeJSON)
}
