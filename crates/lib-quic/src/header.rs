use crate::{
    consts::{
        FIXED_BIT, HEADER_FORM_BIT, PACKET_TYPE_MASK, PACKET_TYPE_SHIFT, PKT_HANDSHAKE,
        PKT_INITIAL, PKT_RETRY, PKT_ZERO_RTT,
    },
    cursor::Cursor,
    error::{Error, Result},
};

#[derive(Debug, PartialEq)]
pub enum PacketType {
    Initial,
    ZeroRtt,
    Handshake,
    Retry,
}

pub struct LongHeader<'a> {
    pub version: u32,
    pub packet_type: PacketType,
    pub dcid: &'a [u8],
    pub scid: &'a [u8],
}

impl<'a> LongHeader<'a> {
    pub fn parse(buf: &[u8]) -> Result<LongHeader<'_>> {
        let mut c = Cursor::new(buf);
        let byte0 = c.u8()?;
        if byte0 & HEADER_FORM_BIT == 0 {
            return Err(Error::NotLongHeader);
        }
        if byte0 & FIXED_BIT == 0 {
            return Err(Error::BadFixedBit);
        }

        let packet_type = match (byte0 & PACKET_TYPE_MASK) >> PACKET_TYPE_SHIFT {
            PKT_INITIAL => PacketType::Initial,
            PKT_ZERO_RTT => PacketType::ZeroRtt,
            PKT_HANDSHAKE => PacketType::Handshake,
            PKT_RETRY => PacketType::Retry,
            _ => unreachable!(),
        };

        let version = c.u32()?;
        let dcid = c.len_prefixed_u8()?;
        let scid = c.len_prefixed_u8()?;
        Ok(LongHeader {
            version,
            packet_type,
            dcid,
            scid,
        })
    }
}
