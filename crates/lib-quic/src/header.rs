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

#[derive(Debug, PartialEq)]
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

// region:    --- Tests

#[cfg(test)]
mod tests {
    type Result<T> = core::result::Result<T, Box<dyn std::error::Error>>; // For tests.

    use super::*;

    #[test]
    fn parses_quic_initial_header_ok() -> Result<()> {
        // Part of the Client Initial packet from RFC 9001 Appendix A.2
        let packet = hex::decode(concat!(
            "c000000001088394c8f03e5157080000",
            "449e7b9aec34d1b1c98dd7689fb8ec11",
            "d242b123dc9bd8bab936b47d92ec356c",
            "0bab7df5976d27cd449f63300099f399",
        ))
        .unwrap();

        let header = LongHeader::parse(&packet)?;

        assert_eq!(header.version, 1);
        assert_eq!(header.packet_type, PacketType::Initial);

        assert_eq!(
            header.dcid,
            &[0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08]
        );

        assert_eq!(header.scid, &[]);
        Ok(())
    }
}

// endregion: --- Tests
