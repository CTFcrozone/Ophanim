use crate::{
    Error, Result,
    consts::{FRAME_CRYPTO, FRAME_PADDING, FRAME_PING},
    cursor::Cursor,
};
use std::collections::BTreeMap;

pub struct CryptoReassembler {
    fragments: BTreeMap<u64, Vec<u8>>,
}

impl CryptoReassembler {
    pub fn new() -> Self {
        Self {
            fragments: BTreeMap::new(),
        }
    }
    pub fn feed_packet(&mut self, plaintext: &[u8]) -> Result<()> {
        let mut c = Cursor::new(plaintext);
        while c.position() < plaintext.len() {
            let frame_type = c.varint()?;
            match frame_type {
                FRAME_PADDING | FRAME_PING => continue,
                FRAME_CRYPTO => {
                    let offset = c.varint()?;
                    let data = c.len_prefixed_varint()?;
                    self.feed_frame(offset, data);
                }
                _ => return Err(Error::UnexpectedFrame),
            }
        }
        Ok(())
    }

    pub fn feed_frame(&mut self, offset: u64, data: &[u8]) {
        self.fragments.insert(offset, data.to_vec());
    }

    pub fn reassemble(&self) -> Option<Vec<u8>> {
        let mut out = Vec::new();
        let mut expected = 0u64;
        for (&offset, data) in &self.fragments {
            if offset != expected {
                return None; // gap - not contiguous from 0 yet
            }
            out.extend_from_slice(data);
            expected += data.len() as u64;
        }
        (!out.is_empty()).then_some(out)
    }
}

// region:    --- Tests

#[cfg(test)]
mod tests {
    type Result<T> = core::result::Result<T, Box<dyn std::error::Error>>; // For tests.

    use super::*;

    #[test]
    fn reassembles_in_order() {
        let mut r = CryptoReassembler::new();
        r.feed_frame(0, &[1, 2, 3]); // see note below
        r.feed_frame(3, &[4, 5, 6]);
        assert_eq!(r.reassemble(), Some(vec![1, 2, 3, 4, 5, 6]));
    }

    #[test]
    fn reassembles_out_of_order() {
        let mut r = CryptoReassembler::new();
        r.feed_frame(3, &[4, 5, 6]);
        r.feed_frame(0, &[1, 2, 3]); // added out of order - BTreeMap sorts
        assert_eq!(r.reassemble(), Some(vec![1, 2, 3, 4, 5, 6]));
    }

    #[test]
    fn detects_gap() {
        let mut r = CryptoReassembler::new();
        r.feed_frame(170, &[9, 9]); // nothing at offset 0
        assert_eq!(r.reassemble(), None);
    }

    #[test]
    fn empty_is_none() {
        let r = CryptoReassembler::new();
        assert_eq!(r.reassemble(), None);
    }
}

// endregion: --- Tests
