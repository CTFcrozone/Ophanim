use crate::{Error, Result};

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

    pub fn u32(&mut self) -> Result<u32> {
        let bytes = self
            .buf
            .get(self.pos..self.pos + 4)
            .ok_or(Error::OutOfBounds)?;
        let bytes: [u8; 4] = bytes.try_into().map_err(|_| Error::OutOfBounds)?;
        self.pos += 4;
        Ok(u32::from_be_bytes(bytes))
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
}
