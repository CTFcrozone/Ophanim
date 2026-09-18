use crate::{
    Error, Result,
    consts::{FRAME_CRYPTO, FRAME_PADDING, FRAME_PING},
    cursor::Cursor,
};

pub fn extract_crypto_data(plaintext: &[u8]) -> Result<&[u8]> {
    let mut c = Cursor::new(plaintext);
    loop {
        let frame_type = c.varint()?;
        match frame_type {
            FRAME_PADDING | FRAME_PING => continue,
            FRAME_CRYPTO => {
                let _offset = c.varint()?;
                let data = c.len_prefixed_varint()?;
                return Ok(data);
            }
            _ => return Err(Error::UnexpectedFrame),
        }
    }
}

// region:    --- Tests

#[cfg(test)]
mod tests {
    type Result<T> = core::result::Result<T, Box<dyn std::error::Error>>; // For tests.

    use crate::{
        consts::TLS_CLIENT_HELLO,
        crypto::{decrypt_payload, derive_initial_keys, remove_header_protection},
        header::InitialHeader,
        test_helpers::packet,
    };

    use super::*;

    #[test]
    fn extracts_crypto_frame() -> Result<()> {
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

        let crypto_data = extract_crypto_data(plaintext)?;

        assert_eq!(crypto_data.len(), 241); // from the 40f1 length varint
        assert_eq!(crypto_data[0], TLS_CLIENT_HELLO); // 0x01
        Ok(())
    }
}

// endregion: --- Tests
