use std::fmt::{Formatter, Error};
use crate::CLIError;
use bluetooth_mesh::device_state;

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
			write!(f, "{:x}", b)?;
		}
		Ok(())
	}
}

pub fn load_file(path: &str, writeable: bool, create: bool) -> Result<std::fs::File, CLIError> {
	std::fs::OpenOptions::new().write(writeable).create(create).open(path).map_err(|e| CLIError::IOError(path.to_owned(), e))
}