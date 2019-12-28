use core::convert::TryInto;
use core::iter::Iterator;
use core::mem;
use core::ops::{Deref, DerefMut, Range};

#[derive(Copy, Clone)]
pub enum Endian {
    Big,
    Little,
    Native,
}

#[derive(Copy, Clone)]
pub struct Bytes<'a> {
    data: &'a [u8],
    length: usize,
}
pub struct BytesMut<'a> {
    data: &'a mut [u8],
    length: usize,
}

impl Bytes<'_> {
    #[must_use]
    pub const fn new_with_length(data: &[u8], length: usize) -> Bytes {
        Bytes { data, length }
    }
    #[must_use]
    pub const fn new(data: &[u8]) -> Bytes {
        Self::new_with_length(data, data.len())
    }
}
impl<'a> From<&'a [u8]> for Bytes<'a> {
    #[must_use]
    fn from(b: &'a [u8]) -> Self {
        Bytes::new(b)
    }
}
impl BytesMut<'_> {
    #[must_use]
    pub fn new_with_length(data: &mut [u8], length: usize) -> BytesMut {
        BytesMut { data, length }
    }
    #[must_use]
    pub fn new_empty(data: &mut [u8]) -> BytesMut {
        Self::new_with_length(data, 0)
    }
    #[must_use]
    pub fn new_full(data: &mut [u8]) -> BytesMut {
        Self::new_with_length(data, data.len())
    }
}
impl<'a> From<&'a mut [u8]> for BytesMut<'a> {
    #[must_use]
    fn from(b: &'a mut [u8]) -> Self {
        BytesMut::new_full(b)
    }
}
#[derive(Copy, Clone, Hash, Eq, PartialEq, Debug)]
pub enum BufError {
    OutOfRange(usize),
    OutOfSpace(usize),
    InvalidIndex(usize),
    BadBytes(usize),
    InvalidInput,
}
pub trait Buf {
    #[must_use]
    fn length(&self) -> usize;
    /// Returns bytes trimmed to 0..capacity()
    #[must_use]
    fn bytes(&self) -> &[u8];
    #[must_use]
    fn capacity(&self) -> usize;
    /// If adding `amount` overflows the length (length() > capacity(), cap it to capacity.
    fn add_length(&mut self, amount: usize);
    /// If subtracting `amount` from length underflow it, set it to zero
    fn sub_length(&mut self, amount: usize);
    fn remaining_empty_space(&self) -> usize {
        self.capacity() - self.length()
    }
    fn ensure_remaining_empty_space(&self, amount: usize) -> Result<(), BufError> {
        if amount > self.remaining_empty_space() {
            Err(BufError::OutOfSpace(self.length() + amount))
        } else {
            Ok(())
        }
    }
    fn ensure_in_range(&self, index: usize) -> Result<(), BufError> {
        if index > self.length() {
            Err(BufError::OutOfRange(index))
        } else {
            Ok(())
        }
    }
    fn pop_front_bytes(&mut self, amount: usize) -> Result<Bytes, BufError>;
    fn slice_to(&self, range: Range<usize>) -> Result<Bytes, BufError> {
        if range.end > self.length() {
            Err(BufError::OutOfRange(range.end))
        } else {
            Ok(Bytes::new(&self.bytes()[range.start..range.end]))
        }
    }
    fn get_n_bytes(&self, index: usize, amount: usize) -> Result<&[u8], BufError> {
        self.ensure_in_range(index + amount)?;
        Ok(&self.bytes()[index..index + amount])
    }
    fn peek_bytes(&self, amount: usize) -> Result<&[u8], BufError> {
        if amount > self.length() {
            Err(BufError::OutOfRange(amount))
        } else {
            Ok(&self.bytes()[self.length() - amount..])
        }
    }
    /// Has to be implemented per type because of lifetime issues
    fn pop_bytes(&mut self, amount: usize) -> Result<&[u8], BufError>;

    #[must_use]
    fn get_at<T: ToFromBytesEndian>(&self, index: usize, endian: Endian) -> Option<T> {
        T::from_bytes_endian(self.get_n_bytes(index, T::byte_size()).ok()?, endian)
    }

    #[must_use]
    fn peek_be<T: ToFromBytesEndian>(&self) -> Option<T> {
        T::from_bytes_be(self.peek_bytes(T::byte_size()).ok()?)
    }
    #[must_use]
    fn peek_le<T: ToFromBytesEndian>(&self) -> Option<T> {
        T::from_bytes_be(self.peek_bytes(T::byte_size()).ok()?)
    }
    fn pop_be<T: ToFromBytesEndian>(&mut self) -> Option<T> {
        let out = self.peek_be()?;
        self.sub_length(T::byte_size());
        Some(out)
    }
    fn pop_le<T: ToFromBytesEndian>(&mut self) -> Option<T> {
        let out = self.peek_le()?;
        self.sub_length(T::byte_size());
        Some(out)
    }
}

pub trait BufMut: Buf {
    #[must_use]
    fn bytes_mut(&mut self) -> &mut [u8];
    fn slice_to_mut(&mut self, range: Range<usize>) -> Result<BytesMut, BufError> {
        if range.end > self.length() {
            Err(BufError::OutOfRange(range.end))
        } else {
            Ok(BytesMut::new_empty(
                &mut self.bytes_mut()[range.start..range.end],
            ))
        }
    }
    fn push_u8(&mut self, value: u8) -> Result<(), BufError> {
        self.ensure_remaining_empty_space(1)?;
        self.add_length(1);
        let l = self.length();
        self.bytes_mut()[l - 1] = value;
        Ok(())
    }
    fn peek_bytes_mut(&mut self, amount: usize) -> Result<&mut [u8], BufError> {
        if amount > self.length() {
            Err(BufError::OutOfRange(amount))
        } else {
            let l = self.length();
            Ok(&mut self.bytes_mut()[l - amount..])
        }
    }
    fn push_bytes_slice(&mut self, slice: &[u8]) -> Result<&[u8], BufError> {
        self.ensure_remaining_empty_space(slice.len())?;
        self.add_length(slice.len());
        let b = self.peek_bytes_mut(slice.len())?;
        b.copy_from_slice(slice);
        Ok(b)
    }
    fn push_bytes_iter<'a, I: Iterator<Item = &'a u8>>(
        &mut self,
        value: I,
    ) -> Result<&[u8], BufError> {
        let (low, high) = value.size_hint();
        self.ensure_remaining_empty_space(high.unwrap_or(low))?;
        let mut count = 0;
        for v in value {
            self.push_u8(*v)?;
            count += 1;
        }
        self.peek_bytes(count)
    }
    fn get_n_bytes_mut(&mut self, index: usize, amount: usize) -> Result<&mut [u8], BufError> {
        self.ensure_in_range(index + amount)?;
        Ok(&mut self.bytes_mut()[index..index + amount])
    }
    fn push_bytes_swapped(&mut self, value: &[u8]) -> Result<&[u8], BufError> {
        self.push_bytes_iter(value.iter().rev())
    }
    fn push_be(&mut self, b: impl ToFromBytesEndian) -> Result<&[u8], BufError> {
        self.push_bytes_slice(b.to_bytes_be().as_ref())
    }
    fn push_le(&mut self, b: impl ToFromBytesEndian) -> Result<&[u8], BufError> {
        self.push_bytes_slice(b.to_bytes_le().as_ref())
    }
}
impl Deref for Bytes<'_> {
    type Target = [u8];

    #[must_use]
    fn deref(&self) -> &Self::Target {
        self.bytes()
    }
}
impl Deref for BytesMut<'_> {
    type Target = [u8];

    #[must_use]
    fn deref(&self) -> &Self::Target {
        self.bytes()
    }
}
impl DerefMut for BytesMut<'_> {
    #[must_use]
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.bytes_mut()
    }
}
impl<'a> Buf for Bytes<'a> {
    #[must_use]
    fn length(&self) -> usize {
        self.length
    }

    #[must_use]
    fn bytes(&self) -> &[u8] {
        &self.data[..self.length]
    }

    #[must_use]
    fn capacity(&self) -> usize {
        self.data.len()
    }

    fn add_length(&mut self, amount: usize) {
        if self.length + amount > self.capacity() {
            self.length = self.capacity()
        } else {
            self.length += amount;
        }
    }
    fn sub_length(&mut self, amount: usize) {
        if amount > self.length {
            self.length = 0
        } else {
            self.length -= amount;
        }
    }

    fn pop_front_bytes(&mut self, amount: usize) -> Result<Bytes, BufError> {
        if amount > self.length() {
            Err(BufError::OutOfRange(amount))
        } else {
            let tmp = mem::replace(&mut self.data, &[]);
            let (bytes, rest) = tmp.split_at(amount);
            self.length -= amount;
            self.data = rest;
            Ok(Bytes::new(bytes))
        }
    }

    fn pop_bytes(&mut self, amount: usize) -> Result<&[u8], BufError> {
        if amount > self.length {
            Err(BufError::InvalidIndex(amount))
        } else {
            let end = self.length;
            let start = self.length - amount;
            self.length -= amount;
            Ok(&self.data[start..end])
        }
    }
}
impl<'a> From<&'a BytesMut<'a>> for Bytes<'a> {
    #[must_use]
    fn from(bytes: &'a BytesMut<'a>) -> Self {
        Bytes {
            data: bytes.data,
            length: bytes.length,
        }
    }
}
impl<'a> Buf for BytesMut<'a> {
    #[must_use]
    fn length(&self) -> usize {
        self.length
    }

    fn pop_front_bytes(&mut self, amount: usize) -> Result<Bytes, BufError> {
        if amount == 0 {
            return Ok(Bytes::new(&self.bytes()[..0]));
        }
        if amount > self.length {
            return Err(BufError::OutOfRange(amount));
        }

        let tmp = mem::replace(&mut self.data, &mut []);
        let (bytes, rest) = tmp.split_at_mut(amount);
        self.length -= amount;
        self.data = rest;
        Ok(Bytes::new(bytes))
    }
    #[must_use]
    fn bytes(&self) -> &[u8] {
        &self.data[..self.length]
    }

    #[must_use]
    fn capacity(&self) -> usize {
        self.data.len()
    }

    fn add_length(&mut self, amount: usize) {
        if self.length + amount > self.capacity() {
            self.length = self.capacity()
        } else {
            self.length += amount;
        }
    }
    fn sub_length(&mut self, amount: usize) {
        if amount > self.length {
            self.length = 0
        } else {
            self.length -= amount;
        }
    }
    fn pop_bytes(&mut self, amount: usize) -> Result<&[u8], BufError> {
        if amount > self.length {
            Err(BufError::InvalidIndex(amount))
        } else {
            let end = self.length;
            let start = self.length - amount;
            self.length -= amount;
            Ok(&self.data[start..end])
        }
    }
}
impl BufMut for BytesMut<'_> {
    fn bytes_mut(&mut self) -> &mut [u8] {
        &mut self.data[..self.length]
    }
}

pub trait ToFromBytesEndian: Sized {
    type AsBytesType: AsRef<[u8]>;

    #[must_use]
    fn byte_size() -> usize {
        core::mem::size_of::<Self::AsBytesType>()
    }

    #[must_use]
    fn to_bytes_le(&self) -> Self::AsBytesType;

    #[must_use]
    fn to_bytes_be(&self) -> Self::AsBytesType;

    #[must_use]
    fn to_bytes_ne(&self) -> Self::AsBytesType {
        if cfg!(target_endian = "big") {
            self.to_bytes_be()
        } else {
            self.to_bytes_le()
        }
    }
    #[must_use]
    fn from_bytes_le(bytes: &[u8]) -> Option<Self>;

    #[must_use]
    fn from_bytes_be(bytes: &[u8]) -> Option<Self>;

    #[must_use]
    fn from_bytes_ne(bytes: &[u8]) -> Option<Self> {
        if cfg!(target_endian = "big") {
            Self::from_bytes_be(bytes)
        } else {
            Self::from_bytes_le(bytes)
        }
    }
    #[must_use]
    fn to_bytes_endian(&self, endian: Endian) -> Self::AsBytesType {
        match endian {
            Endian::Big => self.to_bytes_be(),
            Endian::Little => self.to_bytes_le(),
            Endian::Native => self.to_bytes_ne(),
        }
    }
    #[must_use]
    fn from_bytes_endian(bytes: &[u8], endian: Endian) -> Option<Self> {
        match endian {
            Endian::Big => Self::from_bytes_be(bytes),
            Endian::Little => Self::from_bytes_le(bytes),
            Endian::Native => Self::from_bytes_ne(bytes),
        }
    }
}
/// Implement ToFromEndian for all primitive types (see beneath)
macro_rules! implement_to_from_bytes {
    ( $( $t:ty ), *) => {
        $(
            impl ToFromBytesEndian for $t {
    type AsBytesType = [u8; core::mem::size_of::<Self>()];

    #[must_use]
    fn byte_size() -> usize {
        core::mem::size_of::<Self>()
    }

    #[must_use]
    fn to_bytes_le(&self) -> Self::AsBytesType {
        self.to_le_bytes()
    }

    #[must_use]
    fn to_bytes_be(&self) -> Self::AsBytesType {
        self.to_be_bytes()
    }

    #[must_use]
    fn to_bytes_ne(&self) -> Self::AsBytesType {
        self.to_ne_bytes()
    }

    #[must_use]
    fn from_bytes_le(bytes: &[u8]) -> Option<Self> {
        Some(Self::from_le_bytes(bytes.try_into().ok()?))
    }

    #[must_use]
    fn from_bytes_be(bytes: &[u8]) -> Option<Self> {
        Some(Self::from_be_bytes(bytes.try_into().ok()?))
    }

    #[must_use]
    fn from_bytes_ne(bytes: &[u8]) -> Option<Self> {
        Some(Self::from_ne_bytes(bytes.try_into().ok()?))
    }
}
        )*
    }
}
implement_to_from_bytes!(u8, i8, u16, i16, u32, i32, u64, i64);
