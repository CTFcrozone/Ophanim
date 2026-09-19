use crate::{
    Error, Result,
    consts::{EXT_ALPN, EXT_SNI, EXT_SUPPORTED_VERSIONS, TLS_CLIENT_HELLO},
    cursor::Cursor,
    support::is_grease,
};

pub struct Extension<'a> {
    pub ext_type: u16,
    pub data: &'a [u8],
}

pub struct ClientHello<'a> {
    pub legacy_version: u16,
    pub cipher_suites: &'a [u8],
    pub extensions: Vec<Extension<'a>>,
}

impl<'a> ClientHello<'a> {
    pub fn parse(buf: &'a [u8]) -> Result<ClientHello<'a>> {
        let mut c = Cursor::new(buf);
        // handshake header
        let msg_type = c.u8()?;
        if msg_type != TLS_CLIENT_HELLO {
            return Err(Error::NotClientHello);
        }
        // length of the ClientHello body
        let _body_len = c.u24()?;

        // ClientHello body
        let legacy_version = c.u16()?;
        let _random = c.slice(32)?; // 32-byte random - ignore
        let _session_id = c.len_prefixed_u8()?; // legacy_session_id - ignore
        let cipher_suites = c.len_prefixed_u16()?; // FINGERPRINT
        let _compression = c.len_prefixed_u8()?; // legacy_compression_methods - ignore

        // Extensions block
        let ext_block = c.len_prefixed_u16()?; // the whole extensions list
        let mut ext_cursor = Cursor::new(ext_block);
        let mut extensions = Vec::new();
        while ext_cursor.position() < ext_block.len() {
            let ext_type = ext_cursor.u16()?;
            let data = ext_cursor.len_prefixed_u16()?;
            extensions.push(Extension { ext_type, data });
        }
        Ok(ClientHello {
            legacy_version,
            cipher_suites,
            extensions,
        })
    }

    pub fn tls_version(&self) -> u16 {
        self.extensions
            .iter()
            .find(|e| e.ext_type == EXT_SUPPORTED_VERSIONS)
            .and_then(|e| {
                let list = e.data.get(1..)?; // supported_versions: u8 length prefix
                list.chunks_exact(2)
                    .map(|b| u16::from_be_bytes([b[0], b[1]]))
                    .filter(|&v| !is_grease(v))
                    .max()
            })
            .unwrap_or(self.legacy_version)
    }

    pub fn first_alpn(&self) -> Option<&'a [u8]> {
        self.extensions
            .iter()
            .find(|e| e.ext_type == EXT_ALPN)
            .and_then(|e| {
                let mut c = Cursor::new(e.data);
                c.u16().ok()?;
                c.len_prefixed_u8().ok()
            })
    }

    pub fn has_sni(&self) -> bool {
        self.extensions.iter().any(|e| e.ext_type == EXT_SNI)
    }
}

// region:    --- Tests

#[cfg(test)]
mod tests {
    type Result<T> = core::result::Result<T, Box<dyn std::error::Error>>; // For tests.

    use crate::{
        crypto::{decrypt_payload, derive_initial_keys, remove_header_protection},
        crypto_reassembler::CryptoReassembler,
        header::InitialHeader,
        test_helpers::packet,
    };

    use super::*;

    #[test]
    fn parses_client_hello() -> Result<()> {
        let mut packet = packet();

        let (payload_offset, dcid, length) = {
            let hdr = InitialHeader::parse(&packet)?;
            (hdr.payload_offset, hdr.long.dcid.to_vec(), hdr.length)
        };
        let keys = derive_initial_keys(&dcid)?;
        let unprot = remove_header_protection(&mut packet, payload_offset, &keys.hp)?;
        let plaintext = decrypt_payload(
            &mut packet,
            payload_offset,
            unprot.pn_len,
            unprot.packet_number,
            length,
            &keys.key,
            &keys.iv,
        )?;

        let mut reassembler = CryptoReassembler::new();
        reassembler.feed_packet(plaintext)?;
        let ch_bytes = reassembler.reassemble().ok_or("incomplete ClientHello")?;
        let ch = ClientHello::parse(&ch_bytes)?;

        assert_eq!(ch.legacy_version, 0x0303);
        assert!(!ch.cipher_suites.is_empty());
        assert!(!ch.extensions.is_empty());
        assert!(ch.extensions.iter().any(|e| e.ext_type == 0x0039));
        Ok(())
    }
}

// endregion: --- Tests
