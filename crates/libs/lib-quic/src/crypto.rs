use crate::{Error, consts::*, error::Result};
use aes::{
	Aes128,
	cipher::{Array, BlockCipherEncrypt, KeyInit},
};
use ring::{
	aead::{AES_128_GCM, Aad, LessSafeKey, Nonce, UnboundKey},
	hkdf::{HKDF_SHA256, KeyType, Prk, Salt},
};

pub struct InitialKeys {
	pub key: Vec<u8>, // 16 - AES-128-GCM key
	pub iv: Vec<u8>,  // 12 - nonce base
	pub hp: Vec<u8>,  // 16 - header protection key
}

#[derive(Debug)]
pub struct Unprotected {
	pub packet_number: u64,
	pub pn_len: usize,
}

struct HkdfLen(usize);
impl KeyType for HkdfLen {
	fn len(&self) -> usize {
		self.0
	}
}

pub fn hkdf_expand_label(secret: &Prk, label: &str, length: usize) -> Result<Vec<u8>> {
	let full_label = format!("{HKDF_LABEL_PREFIX}{label}");
	let mut info = Vec::new();
	info.extend_from_slice(&(length as u16).to_be_bytes());
	info.push(full_label.len() as u8);
	info.extend_from_slice(full_label.as_bytes());
	info.push(0);

	let info_slice = info.as_slice();
	let info_parts = [info_slice];

	let okm = secret.expand(&info_parts, HkdfLen(length)).map_err(|_| Error::Crypto)?;
	let mut out = vec![0u8; length];
	okm.fill(&mut out).map_err(|_| Error::Crypto)?;
	Ok(out)
}

pub fn derive_initial_secret(dcid: &[u8]) -> Result<Vec<u8>> {
	let prk = Salt::new(HKDF_SHA256, &INITIAL_SALT).extract(dcid);
	hkdf_expand_label(&prk, HKDF_INITIAL_SECRET_LABEL, HKDF_INITIAL_SECRET_LENGTH)
}

pub fn derive_initial_keys(dcid: &[u8]) -> Result<InitialKeys> {
	let secret = derive_initial_secret(dcid)?;
	let prk = Prk::new_less_safe(HKDF_SHA256, &secret);
	let key = hkdf_expand_label(&prk, HKDF_KEY_LABEL, HKDF_KEY_LENGTH)?;
	let iv = hkdf_expand_label(&prk, HKDF_IV_LABEL, HKDF_IV_LENGTH)?;
	let hp = hkdf_expand_label(&prk, HKDF_HP_LABEL, HKDF_HP_LENGTH)?;
	Ok(InitialKeys { key, iv, hp })
}

fn hp_mask(hp_key: &[u8], sample: &[u8; 16]) -> Result<[u8; 5]> {
	let cipher = Aes128::new_from_slice(hp_key).map_err(|_| Error::Crypto)?;
	let mut block = Array(*sample);
	cipher.encrypt_block(&mut block);
	Ok([block[0], block[1], block[2], block[3], block[4]])
}

pub fn remove_header_protection(packet: &mut [u8], payload_offset: usize, hp_key: &[u8]) -> Result<Unprotected> {
	let sample_start = payload_offset + HP_SAMPLE_OFFSET;
	let sample: &[u8; HP_SAMPLE_LEN] = packet
		.get(sample_start..sample_start + HP_SAMPLE_LEN)
		.ok_or(Error::OutOfBounds)?
		.try_into()
		.map_err(|_| Error::OutOfBounds)?;
	let mask = hp_mask(hp_key, sample)?;
	packet[0] ^= mask[0] & HP_LONG_MASK;
	let pn_len = ((packet[0] & PN_LEN_MASK) + 1) as usize;
	for i in 0..pn_len {
		packet[payload_offset + i] ^= mask[1 + i];
	}
	let mut pn = 0u64;
	for i in 0..pn_len {
		pn = (pn << 8) | packet[payload_offset + i] as u64;
	}
	Ok(Unprotected {
		packet_number: pn,
		pn_len,
	})
}

fn make_nonce(iv: &[u8], packet_number: u64) -> [u8; NONCE_LEN] {
	let mut nonce = [0u8; NONCE_LEN];
	nonce.copy_from_slice(iv);
	let pn_bytes = packet_number.to_be_bytes();
	let offset = NONCE_LEN - pn_bytes.len();
	for i in 0..pn_bytes.len() {
		nonce[offset + i] ^= pn_bytes[i];
	}
	nonce
}

pub fn decrypt_payload<'a>(
	packet: &'a mut [u8],
	payload_offset: usize,
	pn_len: usize,
	packet_number: u64,
	length: u64,
	key: &[u8],
	iv: &[u8],
) -> Result<&'a [u8]> {
	let payload_start = payload_offset + pn_len;
	let ct_len = (length as usize) - pn_len; // ciphertext + tag len
	let (header, rest) = packet.split_at_mut(payload_start);
	let ciphertext = rest.get_mut(..ct_len).ok_or(Error::OutOfBounds)?;
	let unbound = UnboundKey::new(&AES_128_GCM, key).map_err(|_| Error::Crypto)?;
	let aead_key = LessSafeKey::new(unbound);
	let nonce = Nonce::assume_unique_for_key(make_nonce(iv, packet_number));
	let plaintext = aead_key
		.open_in_place(nonce, Aad::from(&*header), ciphertext)
		.map_err(|_| Error::Crypto)?;

	Ok(plaintext)
}

// region:    --- Tests

#[cfg(test)]
mod tests {
	type Result<T> = core::result::Result<T, Box<dyn std::error::Error>>; // For tests.

	use crate::{header::InitialHeader, test_helpers::packet};

	use super::*;

	#[test]
	fn derives_client_initial_secret() -> Result<()> {
		let fx_dcid = hex::decode("8394c8f03e515708")?;
		let secret = derive_initial_secret(&fx_dcid)?;
		let expected = hex::decode("c00cf151ca5be075ed0ebfb5c80323c42d6b7db67881289af4008f1f6c357aea")?;
		assert_eq!(secret, expected);
		Ok(())
	}

	#[test]
	fn derives_initial_keys() -> Result<()> {
		let fx_dcid = hex::decode("8394c8f03e515708")?;
		let keys = derive_initial_keys(&fx_dcid)?;
		assert_eq!(keys.key, hex::decode("1f369613dd76d5467730efcbe3b1a22d")?);
		assert_eq!(keys.iv, hex::decode("fa044b2f42a3fd3b46fb255c")?);
		assert_eq!(keys.hp, hex::decode("9f50449e04a0e810283a1e9933adedd2")?);
		Ok(())
	}

	#[test]
	fn computes_hp_mask() -> Result<()> {
		let hp: Vec<u8> = hex::decode("9f50449e04a0e810283a1e9933adedd2")?;
		let sample: [u8; 16] = hex::decode("d1b1c98dd7689fb8ec11d242b123dc9b")?.try_into().unwrap();
		let mask = hp_mask(&hp, &sample)?;
		assert_eq!(mask.as_slice(), hex::decode("437b9aec36")?.as_slice());
		Ok(())
	}

	#[test]
	fn removes_header_protection() -> Result<()> {
		let mut fx_packet = packet();

		let (payload_offset, dcid) = {
			let hdr = InitialHeader::parse(&fx_packet)?;
			(hdr.payload_offset, hdr.long.dcid.to_vec())
		};

		let keys = derive_initial_keys(&dcid)?;

		let unprotected = remove_header_protection(&mut fx_packet, payload_offset, &keys.hp)?;
		assert_eq!(unprotected.packet_number, 2); // RFC A.2: PN = 2
		assert_eq!(unprotected.pn_len, 4); // 4-byte packet number
		assert_eq!(fx_packet[0], 0xc3); // unprotected byte0
		Ok(())
	}

	#[test]
	fn decrypts_initial_payload() -> Result<()> {
		let mut fx_packet = packet();

		let (payload_offset, dcid, length) = {
			let hdr = InitialHeader::parse(&fx_packet)?;
			(hdr.payload_offset, hdr.long.dcid.to_vec(), hdr.length)
		};
		let keys = derive_initial_keys(&dcid)?;
		let unprot = remove_header_protection(&mut fx_packet, payload_offset, &keys.hp)?;

		let plaintext = decrypt_payload(
			&mut fx_packet,
			payload_offset,
			unprot.pn_len,
			unprot.packet_number,
			length,
			&keys.key,
			&keys.iv,
		)?;

		// RFC A.3: plaintext begins with the CRYPTO frame: 06 00 40 f1 ...
		assert_eq!(&plaintext[..4], &[0x06, 0x00, 0x40, 0xf1]);
		Ok(())
	}
}

// endregion: --- Tests
