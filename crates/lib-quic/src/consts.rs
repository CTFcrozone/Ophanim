// Long header, byte 0 bit layout (RFC 9000 §17.2):
//   7      6      5 4          3 0
//   form | fixed | packet type | type-specific
pub(crate) const HEADER_FORM_BIT: u8 = 0x80; // bit 7  - 1 = long header
pub(crate) const FIXED_BIT: u8 = 0x40; // bit 6  - always 1 in valid QUIC
pub(crate) const PACKET_TYPE_MASK: u8 = 0x30; // bits 5-4
pub(crate) const PACKET_TYPE_SHIFT: u8 = 4; // shift the masked type down to 0..=3
pub(crate) const PKT_INITIAL: u8 = 0;
pub(crate) const PKT_ZERO_RTT: u8 = 1;
pub(crate) const PKT_HANDSHAKE: u8 = 2;
pub(crate) const PKT_RETRY: u8 = 3;
pub(crate) const VARINT_VALUE_MASK: u8 = 0x3F; // 0011_1111
pub(crate) const VARINT_LEN_SHIFT: u8 = 6; // top 2 bits >> 6 give the length class
// Header protection (RFC 9001 §5.4.1)
pub(crate) const HP_SAMPLE_OFFSET: usize = 4; // sample starts 4 bytes past the PN offset (PN is max 4 bytes)
pub(crate) const HP_SAMPLE_LEN: usize = 16; // AES block size - the sample is one block
pub(crate) const HP_LONG_MASK: u8 = 0x0f; // long header: low 4 bits of byte0 are protected
pub(crate) const PN_LEN_MASK: u8 = 0x03; // low 2 bits of byte0 hold (pn_len - 1)
pub(crate) const NONCE_LEN: usize = 12;
// RFC 9001 §5.2
pub(crate) const INITIAL_SALT: [u8; 20] = [
    0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17, 0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad,
    0xcc, 0xbb, 0x7f, 0x0a,
];
// region:    --- RFC 9001 Appendix A.1 Keys
pub(crate) const HKDF_KEY_LENGTH: usize = 16;
pub(crate) const HKDF_IV_LENGTH: usize = 12;
pub(crate) const HKDF_HP_LENGTH: usize = 16;
pub(crate) const HKDF_INITIAL_SECRET_LENGTH: usize = 32;
pub(crate) const HKDF_INITIAL_SECRET_LABEL: &str = "client in";
pub(crate) const HKDF_KEY_LABEL: &str = "quic key";
pub(crate) const HKDF_IV_LABEL: &str = "quic iv";
pub(crate) const HKDF_HP_LABEL: &str = "quic hp";
// endregion: --- RFC 9001 Appendix A.1 Keys
pub(crate) const HKDF_LABEL_PREFIX: &str = "tls13 ";
// QUIC frame types (RFC 9000 §19)
pub(crate) const FRAME_PADDING: u64 = 0x00;
pub(crate) const FRAME_PING: u64 = 0x01;
pub(crate) const FRAME_CRYPTO: u64 = 0x06;

// TLS handshake message types (RFC 8446 §4)
pub(crate) const TLS_CLIENT_HELLO: u8 = 0x01;
pub(crate) const EXT_SNI: u16 = 0x0000;
pub(crate) const EXT_ALPN: u16 = 0x0010;
pub(crate) const EXT_SIGNATURE_ALGORITHMS: u16 = 0x000d;
pub(crate) const EXT_SUPPORTED_VERSIONS: u16 = 0x002b;
