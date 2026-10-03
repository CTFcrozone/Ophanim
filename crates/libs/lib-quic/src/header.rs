use crate::{
	consts::{HEADER_FORM_BIT, MAX_CID_LEN, PACKET_TYPE_MASK, PACKET_TYPE_SHIFT, V1, V2},
	cursor::Cursor,
	error::{Error, Result},
};

#[derive(Debug, PartialEq)]
pub enum PacketType {
	Initial,
	ZeroRtt,
	Handshake,
	Retry,
	VersionNegotiation,
	Unknown,
}

#[derive(Debug, PartialEq)]
pub struct LongHeader<'a> {
	pub version: u32,
	pub packet_type: PacketType,
	pub dcid: &'a [u8],
	pub scid: &'a [u8],
	pub token: &'a [u8], // Initial only, empty otherwise
	pub length: u64,     // pn + payload length; 0 for Retry / Version Negotiation
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
		let token = long.token;
		let length = long.length;
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

		let version = c.u32()?;

		let type_bits = (byte0 & PACKET_TYPE_MASK) >> PACKET_TYPE_SHIFT;
		let packet_type = match version {
			0 => PacketType::VersionNegotiation,
			V1 => match type_bits {
				0 => PacketType::Initial,
				1 => PacketType::ZeroRtt,
				2 => PacketType::Handshake,
				_ => PacketType::Retry,
			},
			V2 => match type_bits {
				1 => PacketType::Initial,
				2 => PacketType::ZeroRtt,
				3 => PacketType::Handshake,
				_ => PacketType::Retry,
			},
			_ => PacketType::Unknown,
		};

		let dcid = c.len_prefixed_u8()?;
		let scid = c.len_prefixed_u8()?;

		if matches!(version, V1 | V2) && (dcid.len() > MAX_CID_LEN || scid.len() > MAX_CID_LEN) {
			return Err(Error::BadConnectionIdLength);
		}
		let (token, length) = match packet_type {
			PacketType::Initial => {
				let token = c.len_prefixed_varint()?;
				(token, c.varint()?)
			}
			PacketType::ZeroRtt | PacketType::Handshake => (&[][..], c.varint()?),
			PacketType::Retry | PacketType::VersionNegotiation | PacketType::Unknown => (&[][..], 0),
		};

		Ok(LongHeader {
			version,
			packet_type,
			dcid,
			scid,
			token,
			length,
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

		assert_eq!(header.dcid, &[0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08]);

		assert_eq!(header.scid, &[]);
		Ok(())
	}

	#[test]
	fn parses_v2_initial_header() -> Result<()> {
		// RFC 9369 A.2, protected header only
		let buf = [
			0xd7, 0x6b, 0x33, 0x43, 0xcf, 0x08, 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08, 0x00, 0x00, 0x44, 0x9e,
		];
		let hdr = InitialHeader::parse(&buf)?;
		assert_eq!(hdr.long.version, V2);
		assert_eq!(hdr.long.packet_type, PacketType::Initial);
		assert_eq!(hdr.length, 1182);
		assert_eq!(hdr.payload_offset, 18);
		Ok(())
	}

	#[test]
	fn version_negotiation_and_unknown_versions() -> Result<()> {
		// VN with the fixed bit clear
		let vn = [0x80, 0, 0, 0, 0, 0x01, 0xaa, 0x01, 0xbb, 0, 0, 0, 1];
		let h = LongHeader::parse(&mut Cursor::new(&vn))?;
		assert_eq!(h.packet_type, PacketType::VersionNegotiation);
		assert_eq!(h.dcid, &[0xaa]);

		// Greased version: only the CIDs are parsed
		let grease = [0xc0, 0x1a, 0x2a, 0x3a, 0x4a, 0x01, 0xaa, 0x01, 0xbb, 0xff];
		let h = LongHeader::parse(&mut Cursor::new(&grease))?;
		assert_eq!(h.packet_type, PacketType::Unknown);
		assert_eq!(h.length, 0);
		Ok(())
	}

	#[test]
	fn rejects_long_cid_on_v1_only() {
		let mut buf = vec![0xc0, 0, 0, 0, 1, 21];
		buf.extend([0u8; 21]);
		buf.extend([0, 0, 0]);
		assert!(LongHeader::parse(&mut Cursor::new(&buf)).is_err());

		buf[1..5].copy_from_slice(&[0x1a, 0x2a, 0x3a, 0x4a]);
		assert!(LongHeader::parse(&mut Cursor::new(&buf)).is_ok());
	}

	#[test]
	fn parses_full_initial_header() -> Result<()> {
		// Full client Initial packet from RFC 9001 Appendix A.1 (1200 bytes, padded)
		let fx_packet = packet();

		let hdr = InitialHeader::parse(&fx_packet)?;

		assert_eq!(hdr.long.version, 1);
		assert_eq!(hdr.long.packet_type, PacketType::Initial);
		assert_eq!(hdr.long.dcid, &[0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08]);
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
