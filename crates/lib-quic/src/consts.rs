// Long header, byte 0 bit layout (RFC 9000 §17.2):
//   7      6      5 4          3 0
//   form | fixed | packet type | type-specific
pub const HEADER_FORM_BIT: u8 = 0x80; // bit 7  - 1 = long header
pub const FIXED_BIT: u8 = 0x40; // bit 6  - always 1 in valid QUIC
pub const PACKET_TYPE_MASK: u8 = 0x30; // bits 5-4
pub const PACKET_TYPE_SHIFT: u8 = 4; // shift the masked type down to 0..=3
pub const PKT_INITIAL: u8 = 0;
pub const PKT_ZERO_RTT: u8 = 1;
pub const PKT_HANDSHAKE: u8 = 2;
pub const PKT_RETRY: u8 = 3;
pub const BYTE0: usize = 0;
pub const VERSION_OFFSET: usize = 1;
pub const VERSION_LEN: usize = 4;
pub const DCID_LEN_OFFSET: usize = 5; // where the DCID length byte sits
pub const FIRST_CID_OFFSET: usize = 6; // where the DCID bytes start
