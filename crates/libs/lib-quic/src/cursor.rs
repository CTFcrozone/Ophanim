use crate::{
	Error, Result,
	consts::{VARINT_LEN_SHIFT, VARINT_VALUE_MASK},
};

pub struct Cursor<'a> {
	buf: &'a [u8],
	pos: usize,
}

impl<'a> Cursor<'a> {
	pub fn new(buf: &'a [u8]) -> Cursor<'a> {
		Self { buf, pos: 0 }
	}
	pub fn u8(&mut self) -> Result<u8> {
		let byte = *self.buf.get(self.pos).ok_or(Error::OutOfBounds)?;
		self.pos += 1;
		Ok(byte)
	}

	pub fn u16(&mut self) -> Result<u16> {
		let bytes = self.buf.get(self.pos..self.pos + 2).ok_or(Error::OutOfBounds)?;
		let bytes: [u8; 2] = bytes.try_into().map_err(|_| Error::OutOfBounds)?;
		self.pos += 2;
		Ok(u16::from_be_bytes(bytes))
	}

	pub fn len_prefixed_u16(&mut self) -> Result<&'a [u8]> {
		let n = self.u16()?;
		self.slice(n as usize)
	}

	pub fn u32(&mut self) -> Result<u32> {
		let bytes = self.buf.get(self.pos..self.pos + 4).ok_or(Error::OutOfBounds)?;
		let bytes: [u8; 4] = bytes.try_into().map_err(|_| Error::OutOfBounds)?;
		self.pos += 4;
		Ok(u32::from_be_bytes(bytes))
	}

	pub fn u24(&mut self) -> Result<u32> {
		let b = self.slice(3)?;
		Ok((b[0] as u32) << 16 | (b[1] as u32) << 8 | b[2] as u32)
	}

	pub fn slice(&mut self, n: usize) -> Result<&'a [u8]> {
		let end = self.pos.checked_add(n).ok_or(Error::OutOfBounds)?;
		let bytes = self.buf.get(self.pos..end).ok_or(Error::OutOfBounds)?;
		self.pos = end;
		Ok(bytes)
	}

	pub fn len_prefixed_u8(&mut self) -> Result<&'a [u8]> {
		let n = self.u8()?;
		self.slice(n as usize)
	}

	pub fn len_prefixed_varint(&mut self) -> Result<&'a [u8]> {
		let n = self.varint()?;
		self.slice(n as usize)
	}

	pub fn varint(&mut self) -> Result<u64> {
		let first = self.u8()?;
		let prefix = first >> VARINT_LEN_SHIFT; // top 2 bits
		let len = 1usize << prefix;
		let mut value = (first & VARINT_VALUE_MASK) as u64; // low 6 bits of first byte

		// read the remaining len-1 bytes
		for _ in 1..len {
			let b = self.u8()?;
			value = (value << 8) | b as u64;
		}
		Ok(value)
	}

	pub fn position(&self) -> usize {
		self.pos
	}
}
