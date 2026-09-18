use crate::{Error, error::Result};
use ring::hkdf::{HKDF_SHA256, KeyType, Prk, Salt};

// RFC 9001 §5.2
pub const INITIAL_SALT: [u8; 20] = [
    0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17, 0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad,
    0xcc, 0xbb, 0x7f, 0x0a,
];

pub const HKDF_INITIAL_SECRET_LABEL: &str = "client in";
pub const HKDF_KEY_LABEL: &str = "quic key";
pub const HKDF_KEY_LENGTH: usize = 16;
pub const HKDF_IV_LENGTH: usize = 12;
pub const HKDF_HP_LENGTH: usize = 16;
pub const HKDF_IV_LABEL: &str = "quic iv";
pub const HKDF_HP_LABEL: &str = "quic hp";
pub const HKDF_LABEL_PREFIX: &str = "tls13 ";

pub struct InitialKeys {
    pub key: Vec<u8>, // 16 - AES-128-GCM key
    pub iv: Vec<u8>,  // 12 - nonce base
    pub hp: Vec<u8>,  // 16 - header protection key
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

    let okm = secret
        .expand(&info_parts, HkdfLen(length))
        .map_err(|_| Error::Crypto)?;
    let mut out = vec![0u8; length];
    okm.fill(&mut out).map_err(|_| Error::Crypto)?;
    Ok(out)
}

pub fn derive_initial_secret(dcid: &[u8]) -> Result<Vec<u8>> {
    let prk = Salt::new(HKDF_SHA256, &INITIAL_SALT).extract(dcid);
    hkdf_expand_label(&prk, HKDF_INITIAL_SECRET_LABEL, 32)
}

pub fn derive_initial_keys(dcid: &[u8]) -> Result<InitialKeys> {
    let secret = derive_initial_secret(dcid)?;
    let prk = Prk::new_less_safe(HKDF_SHA256, &secret);
    let key = hkdf_expand_label(&prk, HKDF_KEY_LABEL, HKDF_KEY_LENGTH)?;
    let iv = hkdf_expand_label(&prk, HKDF_IV_LABEL, HKDF_IV_LENGTH)?;
    let hp = hkdf_expand_label(&prk, HKDF_HP_LABEL, HKDF_HP_LENGTH)?;
    Ok(InitialKeys { key, iv, hp })
}

// region:    --- Tests

#[cfg(test)]
mod tests {
    type Result<T> = core::result::Result<T, Box<dyn std::error::Error>>; // For tests.

    use super::*;

    #[test]
    fn derives_client_initial_secret() -> Result<()> {
        let fx_dcid = hex::decode("8394c8f03e515708")?;
        let secret = derive_initial_secret(&fx_dcid)?;
        let expected =
            hex::decode("c00cf151ca5be075ed0ebfb5c80323c42d6b7db67881289af4008f1f6c357aea")?;
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
}

// endregion: --- Tests
