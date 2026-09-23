use std::path::Path;

use clap::Parser as _;
use lib_quic::{
	ClientHello, CryptoReassembler, InitialHeader, PacketType, decrypt_payload, derive_initial_keys,
	remove_header_protection,
};
use pcap::Capture;
use pnet_packet::{
	Packet,
	ethernet::{EtherTypes, EthernetPacket},
	ip::IpNextHeaderProtocols,
	ipv4::Ipv4Packet,
	ipv6::Ipv6Packet,
	udp::UdpPacket,
};

use crate::{
	Error, Result,
	cli::cmd::{CliCmd, Mode},
};

#[derive(Default)]
pub struct QuicSummary {
	pub version: u32,
	pub packets: usize,
	pub initial_packets: usize,
	pub handshake_packets: usize,
	pub zero_rtt_packets: usize,
	pub retry_packets: usize,
	pub dcid: String,
	pub scid: String,
}

pub struct TlsSummary {
	pub version: String,
	pub sni: Option<String>,
	pub alpn: Option<String>,
	pub cipher_suites: usize,
	pub extensions: usize,
}

pub struct Summary {
	pub quic: QuicSummary,
	pub tls: Option<TlsSummary>,
	pub ja4: Option<String>,
}

pub fn execute() -> Result<()> {
	let cli = CliCmd::parse();

	match cli.command {
		Mode::Summary => summary(&cli.path),
		Mode::Tls => tls(&cli.path),
		Mode::Ja4 => ja4(&cli.path),
		Mode::Verbose => verbose(&cli.path),
	}
}

fn udp_payload(packet: &[u8]) -> Option<Vec<u8>> {
	let ethernet = EthernetPacket::new(packet)?;

	match ethernet.get_ethertype() {
		EtherTypes::Ipv4 => {
			let ipv4 = Ipv4Packet::new(ethernet.payload())?;

			if ipv4.get_next_level_protocol() != IpNextHeaderProtocols::Udp {
				return None;
			}

			let udp = UdpPacket::new(ipv4.payload())?;

			Some(udp.payload().to_vec())
		}

		EtherTypes::Ipv6 => {
			let ipv6 = Ipv6Packet::new(ethernet.payload())?;

			if ipv6.get_next_header() != IpNextHeaderProtocols::Udp {
				return None;
			}

			let udp = UdpPacket::new(ipv6.payload())?;

			Some(udp.payload().to_vec())
		}

		_ => None,
	}
}

// region:    --- Executors
pub fn summary(path: &Path) -> Result<()> {
	let mut cap = Capture::from_file(path)?;
	let mut reassembler = CryptoReassembler::new();

	Ok(())
}
pub fn tls(path: &Path) -> Result<()> {
	let mut cap = Capture::from_file(path)?;
	let mut reassembler = CryptoReassembler::new();

	while let Ok(packet) = cap.next_packet() {
		let mut data = match udp_payload(packet.data) {
			Some(data) => data,
			None => continue,
		};

		let (packet_type, dcid, payload_offset, length) = {
			let header = match InitialHeader::parse(&data) {
				Ok(header) => header,
				Err(_) => continue,
			};

			(
				header.long.packet_type,
				header.long.dcid.to_vec(),
				header.payload_offset,
				header.length,
			)
		};

		if packet_type != PacketType::Initial {
			continue;
		}

		let keys = derive_initial_keys(&dcid)?;

		let unprotected = remove_header_protection(&mut data, payload_offset, &keys.hp)?;

		let plaintext = decrypt_payload(
			&mut data,
			payload_offset,
			unprotected.pn_len,
			unprotected.packet_number,
			length,
			&keys.key,
			&keys.iv,
		)?;

		reassembler.feed_packet(plaintext)?;

		let Some(ch_bytes) = reassembler.reassemble() else {
			continue;
		};

		let ch = ClientHello::parse(&ch_bytes)?;

		print_tls(&ch);

		return Ok(());
	}

	Err(Error::custom("TLS ClientHello not found"))
}
pub fn ja4(path: &Path) -> Result<()> {
	let mut cap = Capture::from_file(path)?;
	let mut reassembler = CryptoReassembler::new();

	while let Ok(packet) = cap.next_packet() {
		let mut data = match udp_payload(packet.data) {
			Some(data) => data,
			None => continue,
		};

		let (packet_type, dcid, payload_offset, length) = {
			let header = match InitialHeader::parse(&data) {
				Ok(header) => header,
				Err(_) => continue,
			};

			(
				header.long.packet_type,
				header.long.dcid.to_vec(),
				header.payload_offset,
				header.length,
			)
		};

		if packet_type != PacketType::Initial {
			continue;
		}

		let keys = derive_initial_keys(&dcid)?;

		let unprotected = remove_header_protection(&mut data, payload_offset, &keys.hp)?;

		let plaintext = decrypt_payload(
			&mut data,
			payload_offset,
			unprotected.pn_len,
			unprotected.packet_number,
			length,
			&keys.key,
			&keys.iv,
		)?;

		reassembler.feed_packet(plaintext)?;

		let Some(ch_bytes) = reassembler.reassemble() else {
			continue;
		};

		let ch = ClientHello::parse(&ch_bytes)?;

		println!("{}", lib_quic::ja4(&ch));

		return Ok(());
	}

	Err(Error::custom("TLS ClientHello not found; cannot calculate JA4QUIC"))
}
pub fn verbose(path: &Path) -> Result<()> {
	let mut cap = Capture::from_file(path)?;
	let mut packet_number = 0usize;

	while let Ok(packet) = cap.next_packet() {
		packet_number += 1;

		let data = match udp_payload(packet.data) {
			Some(data) => data,
			None => continue,
		};

		println!("Packet #{packet_number}");
		println!("────────────────────────────────");

		let mut cursor = lib_quic::Cursor::new(&data);

		let header = match lib_quic::LongHeader::parse(&mut cursor) {
			Ok(header) => header,
			Err(err) => {
				println!(" Invalid QUIC packet: {err}");
				println!();
				continue;
			}
		};

		println!(" QUIC Version : {}", header.version);
		println!(" Type         : {:?}", header.packet_type);
		println!(" DCID         : {}", hex::encode(header.dcid));
		println!(" SCID         : {}", hex::encode(header.scid));
		println!();
	}

	Ok(())
}
// endregion: --- Executors

// region:    --- Display
fn tls_summary_from_client_hello(ch: &ClientHello<'_>) -> TlsSummary {
	TlsSummary {
		version: tls_version_string(ch.tls_version()),
		sni: None,
		alpn: ch.first_alpn().map(|alpn| String::from_utf8_lossy(alpn).into_owned()),
		cipher_suites: ch.cipher_suites.len() / 2,
		extensions: ch.extensions.len(),
	}
}
fn print_summary(summary: &Summary) {
	println!("Ophanim - QUIC Summary");
	println!("════════════════════════════════════");
	println!();
	println!("Connection");
	println!(" QUIC Version {}", summary.quic.version);
	println!(" DCID {}", summary.quic.dcid);
	println!(" SCID {}", summary.quic.scid);
	println!();
	println!("Packets");
	println!(" Total {}", summary.quic.packets);
	println!(" Initial {}", summary.quic.initial_packets);
	println!(" 0-RTT {}", summary.quic.zero_rtt_packets);
	println!(" Handshake {}", summary.quic.handshake_packets);
	println!(" Retry {}", summary.quic.retry_packets);
	if let Some(tls) = &summary.tls {
		println!();
		println!("TLS");
		println!(" Version {}", tls.version);
		println!(" SNI {}", tls.sni.as_deref().unwrap_or("-"));
		println!(" ALPN {}", tls.alpn.as_deref().unwrap_or("-"));
		println!(" Cipher Suites {}", tls.cipher_suites);
		println!(" Extensions {}", tls.extensions);
	}
	if let Some(ja4) = &summary.ja4 {
		println!();
		println!("Fingerprint");
		println!(" JA4QUIC {ja4}");
	}
	println!();
}
fn print_tls(ch: &ClientHello<'_>) {
	println!("TLS ClientHello");
	println!("════════════════════════════════════");
	println!();

	println!(" Version         0x{:04x}", ch.tls_version());

	println!(
		" ALPN            {}",
		ch.first_alpn()
			.map(|x| String::from_utf8_lossy(x).into_owned())
			.unwrap_or_else(|| "-".to_string())
	);

	println!(" Cipher Suites   {}", ch.cipher_suites.len() / 2);
	println!(" Extensions      {}", ch.extensions.len());
	println!(" SNI             {}", if ch.has_sni() { "yes" } else { "no" });
}
// endregion: --- Display

fn tls_version_string(version: u16) -> String {
	match version {
		0x0304 => "TLS 1.3".to_string(),
		0x0303 => "TLS 1.2".to_string(),
		0x0302 => "TLS 1.1".to_string(),
		0x0301 => "TLS 1.0".to_string(),
		_ => format!("0x{version:04x}"),
	}
}
