use crate::{
    consts::{EXT_ALPN, EXT_SIGNATURE_ALGORITHMS, EXT_SNI},
    support::{is_grease, sig_algs_hex, truncated_sha256},
    tls::{ClientHello, Extension},
};

// SHA-256 (first 12 hex) of the sorted, GREASE-filtered
// cipher suites, formatted as 4-hex codes joined by commas
fn ja4_ciphers(cipher_suites: &[u8]) -> String {
    let mut codes: Vec<u16> = cipher_suites
        .chunks_exact(2) // each cipher = 2 bytes
        .map(|c| u16::from_be_bytes([c[0], c[1]]))
        .filter(|&c| !is_grease(c))
        .collect();
    codes.sort_unstable();

    let joined = codes
        .iter()
        .map(|c| format!("{c:04x}")) // 4 lowercase hex digits
        .collect::<Vec<_>>()
        .join(",");

    truncated_sha256(&joined)
}

fn ja4_extensions(extensions: &[Extension]) -> String {
    let mut ext_codes: Vec<u16> = extensions
        .iter()
        .map(|e| e.ext_type)
        .filter(|&t| !is_grease(t) && t != EXT_SNI && t != EXT_ALPN)
        .collect();
    ext_codes.sort_unstable();
    let ext_part = ext_codes
        .iter()
        .map(|c| format!("{c:04x}"))
        .collect::<Vec<_>>()
        .join(",");

    let sig_part = extensions
        .iter()
        .find(|e| e.ext_type == EXT_SIGNATURE_ALGORITHMS)
        .map(|e| sig_algs_hex(e.data))
        .unwrap_or_default();

    let combined = format!("{ext_part}_{sig_part}");
    truncated_sha256(&combined)
}

fn ja4_version_str(v: u16) -> &'static str {
    match v {
        0x0304 => "13", // TLS 1.3
        0x0303 => "12",
        0x0302 => "11",
        0x0301 => "10",
        _ => "00",
    }
}

fn ja4_alpn_str(ch: &ClientHello) -> String {
    match ch.first_alpn() {
        Some(p) if !p.is_empty() => {
            let first = p[0] as char;
            let last = p[p.len() - 1] as char;
            format!("{first}{last}")
        }
        _ => "00".to_string(),
    }
}

fn ja4_a(ch: &ClientHello) -> String {
    let version = ja4_version_str(ch.tls_version());
    let sni = if ch.has_sni() { 'd' } else { 'i' };

    let cipher_count = ch
        .cipher_suites
        .chunks_exact(2)
        .map(|c| u16::from_be_bytes([c[0], c[1]]))
        .filter(|&c| !is_grease(c))
        .count()
        .min(99);

    let ext_count = ch
        .extensions
        .iter()
        .filter(|e| !is_grease(e.ext_type))
        .count()
        .min(99);

    let alpn = ja4_alpn_str(ch);

    format!("q{version}{sni}{cipher_count:02}{ext_count:02}{alpn}")
}

pub fn ja4(ch: &ClientHello) -> String {
    format!(
        "{}_{}_{}",
        ja4_a(ch),
        ja4_ciphers(ch.cipher_suites),
        ja4_extensions(&ch.extensions),
    )
}

#[cfg(test)]
mod tests {
    type Result<T> = core::result::Result<T, Box<dyn std::error::Error>>;
    use super::*;
    use crate::{
        crypto::{decrypt_payload, derive_initial_keys, remove_header_protection},
        crypto_reassembler::CryptoReassembler,
        header::InitialHeader,
        test_helpers::{CLIENT1_PACKET, CLIENT2_PACKET, packet},
    };

    #[test]
    fn computes_ja4_fingerprint() -> Result<()> {
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

        let fp = ja4(&ch);
        assert!(fp.starts_with('q'));
        assert_eq!(fp.matches('_').count(), 2);
        println!("JA4QUIC: {fp}");
        Ok(())
    }

    #[test]
    fn fingerprints_fragmented_real_capture() -> Result<()> {
        // Real Chrome HTTP/3 client Initials (same connection, DCID 8bc42c...).
        // The ClientHello (1889 bytes) is fragmented across both packets, so this
        // exercises the reassembler. Reference JA4QUIC from Wireshark 4.7.2.

        let mut reassembler = CryptoReassembler::new();

        for hex_str in [CLIENT1_PACKET, CLIENT2_PACKET] {
            let mut packet = hex::decode(hex_str)?;
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
            reassembler.feed_packet(plaintext)?;
        }

        let ch_bytes = reassembler.reassemble().ok_or("incomplete ClientHello")?;
        let ch = ClientHello::parse(&ch_bytes)?;
        let fp = ja4(&ch);

        assert_eq!(fp, "q13d0315h3_55b375c5d22e_dc5437974b47");
        Ok(())
    }
}
