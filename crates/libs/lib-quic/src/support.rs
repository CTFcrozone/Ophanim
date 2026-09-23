use ring::digest::{SHA256, digest};

use crate::cursor::Cursor;

// GREASE values (RFC 8701) follow the pattern 0x?a?a - high byte equals low byte,
// and the low nibble of each is 0xa (e.g. 0x0a0a, 0x1a1a, ... 0xfafa).
pub(crate) fn is_grease(v: u16) -> bool {
	let hi = (v >> 8) as u8;
	let lo = (v & 0xff) as u8;
	hi == lo && (hi & 0x0f) == 0x0a
}

pub(crate) fn truncated_sha256(input: &str) -> String {
	let d = digest(&SHA256, input.as_bytes());
	hex::encode(&d.as_ref()[..6]) // JA4 uses the first 12 hex chars = 6 bytes
}

pub(crate) fn sig_algs_hex(ext_data: &[u8]) -> String {
	let mut c = Cursor::new(ext_data);
	let list = match c.len_prefixed_u16() {
		Ok(l) => l,
		Err(_) => return String::new(),
	};
	list.chunks_exact(2)
		.map(|b| format!("{:04x}", u16::from_be_bytes([b[0], b[1]])))
		.collect::<Vec<_>>()
		.join(",")
}
