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

pub struct InitialHeader<'a> {
    pub long: LongHeader<'a>,
    pub token: &'a [u8],
    pub length: u64,
    pub payload_offset: usize,
}

impl<'a> InitialHeader<'a> {
    pub fn parse(buf: &'a [u8]) -> Result<InitialHeader<'a>> {
        let mut c = Cursor::new(buf);
        let long = LongHeader::parse(&mut c)?;
        if long.packet_type != PacketType::Initial {
            return Err(Error::NotInitial);
        }
        let token = c.len_prefixed_varint()?;
        let length = c.varint()?;
        let payload_offset = c.position();
        Ok(InitialHeader {
            long,
            token,
            length,
            payload_offset,
        })
    }
}

impl<'a> LongHeader<'a> {
    pub fn parse(c: &mut Cursor<'a>) -> Result<LongHeader<'a>> {
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

    use crate::test_helpers::packet;

    use super::*;

    #[test]
    fn parses_long_header_ok() -> Result<()> {
        // Part of the Client Initial packet from RFC 9001 Appendix A.2
        let fx_packet = packet();

        let mut c = Cursor::new(&fx_packet);
        let header = LongHeader::parse(&mut c)?;

        assert_eq!(header.version, 1);
        assert_eq!(header.packet_type, PacketType::Initial);

        assert_eq!(
            header.dcid,
            &[0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08]
        );

        assert_eq!(header.scid, &[]);
        Ok(())
    }

    #[test]
    fn parses_full_initial_header() -> Result<()> {
        // Full client Initial packet from RFC 9001 Appendix A.1 (1200 bytes, padded)
        let fx_packet = packet();

        let hdr = InitialHeader::parse(&fx_packet)?;

        assert_eq!(hdr.long.version, 1);
        assert_eq!(hdr.long.packet_type, PacketType::Initial);
        assert_eq!(
            hdr.long.dcid,
            &[0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08]
        );
        assert_eq!(hdr.long.scid, &[] as &[u8]);
        assert_eq!(hdr.token, &[] as &[u8]);
        assert_eq!(hdr.length, 1182);
        assert_eq!(hdr.payload_offset, 18);

        //  header + declared length must equal the whole packet
        assert_eq!(hdr.payload_offset + hdr.length as usize, fx_packet.len());
        Ok(())
    }
}

// endregion: --- Tests
