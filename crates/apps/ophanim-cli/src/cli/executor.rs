use std::{
	collections::{HashMap, HashSet},
	path::Path,
};

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
	pub sni: bool,
	pub alpn: Option<String>,
	pub cipher_suites: usize,
	pub extensions: usize,
}

pub struct Summary {
	pub quic: QuicSummary,
	pub tls: Option<TlsSummary>,
	pub ja4: Option<String>,
}

pub struct ConnFingerprint {
	pub dcid: String,
	pub ja4: String,
	pub version: String,
	pub sni: bool,
	pub alpn: Option<String>,
	pub cipher_suites: usize,
	pub extensions: usize,
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

// region:    --- Packet helpers
/// Pull the UDP payload out of an Ethernet frame (IPv4 or IPv6), if it is UDP.
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
fn feed_initial(
	reassemblers: &mut HashMap<Vec<u8>, CryptoReassembler>,
	mut data: Vec<u8>,
) -> Option<(Vec<u8>, Vec<u8>)> {
	let header = InitialHeader::parse(&data).ok()?;

	if header.long.packet_type != PacketType::Initial {
		return None;
	}

	let dcid = header.long.dcid.to_vec();
	let payload_offset = header.payload_offset;
	let length = header.length;

	let keys = derive_initial_keys(&dcid).ok()?;
	let unprot = remove_header_protection(&mut data, payload_offset, &keys.hp).ok()?;
	let plaintext = decrypt_payload(
		&mut data,
		payload_offset,
		unprot.pn_len,
		unprot.packet_number,
		length,
		&keys.key,
		&keys.iv,
	)
	.ok()?;

	let reassembler = reassemblers.entry(dcid.clone()).or_insert_with(CryptoReassembler::new);
	reassembler.feed_packet(plaintext).ok()?;
	let ch_bytes = reassembler.reassemble()?;
	Some((dcid, ch_bytes))
}
// endregion: --- Packet helpers

// region:    --- Executors

fn collect_fingerprints(path: &Path, mut on_packet: impl FnMut(&[u8])) -> Result<Vec<ConnFingerprint>> {
	let mut cap = Capture::from_file(path)?;
	let mut reassemblers: HashMap<Vec<u8>, CryptoReassembler> = HashMap::new();
	let mut done: HashSet<Vec<u8>> = HashSet::new();
	let mut out = Vec::new();

	while let Ok(packet) = cap.next_packet() {
		let Some(data) = udp_payload(packet.data) else { continue };
		on_packet(&data);

		if let Some((dcid, ch_bytes)) = feed_initial(&mut reassemblers, data) {
			if done.contains(&dcid) {
				continue;
			}
			let ch = ClientHello::parse(&ch_bytes)?;
			out.push(ConnFingerprint {
				dcid: hex::encode(&dcid),
				ja4: lib_quic::ja4(&ch),
				version: tls_version_string(ch.tls_version()),
				sni: ch.has_sni(),
				alpn: ch.first_alpn().map(|a| String::from_utf8_lossy(a).into_owned()),
				cipher_suites: ch.cipher_suites.len() / 2,
				extensions: ch.extensions.len(),
			});
			done.insert(dcid);
		}
	}
	Ok(out)
}
pub fn ja4(path: &Path) -> Result<()> {
	let fps = collect_fingerprints(path, |_| {})?;
	if fps.is_empty() {
		return Err(Error::custom("no QUIC ClientHello found"));
	}
	for fp in &fps {
		println!("{}  {}", fp.dcid, fp.ja4);
	}
	Ok(())
}

pub fn tls(path: &Path) -> Result<()> {
	let fps = collect_fingerprints(path, |_| {})?;
	let Some(fp) = fps.first() else {
		return Err(Error::custom("TLS ClientHello not found"));
	};
	print_tls(fp);
	Ok(())
}

pub fn summary(path: &Path) -> Result<()> {
	let mut quic = QuicSummary::default();
	let mut first_ids: Option<(String, String, u32)> = None;

	let fps = collect_fingerprints(path, |data| {
		let mut cursor = lib_quic::Cursor::new(data);
		if let Ok(header) = lib_quic::LongHeader::parse(&mut cursor) {
			quic.packets += 1;
			match header.packet_type {
				PacketType::Initial => quic.initial_packets += 1,
				PacketType::Handshake => quic.handshake_packets += 1,
				PacketType::ZeroRtt => quic.zero_rtt_packets += 1,
				PacketType::Retry => quic.retry_packets += 1,
			}
			if first_ids.is_none() {
				first_ids = Some((hex::encode(header.dcid), hex::encode(header.scid), header.version));
			}
		}
	})?;

	if let Some((dcid, scid, version)) = first_ids {
		quic.dcid = dcid;
		quic.scid = scid;
		quic.version = version;
	}

	let (tls, ja4) = match fps.first() {
		Some(fp) => (
			Some(TlsSummary {
				version: fp.version.clone(),
				sni: fp.sni,
				alpn: fp.alpn.clone(),
				cipher_suites: fp.cipher_suites,
				extensions: fp.extensions,
			}),
			Some(fp.ja4.clone()),
		),
		None => (None, None),
	};

	print_summary(&Summary { quic, tls, ja4 });
	Ok(())
}

pub fn verbose(path: &Path) -> Result<()> {
	let mut cap = Capture::from_file(path)?;
	let mut packet_number = 0usize;

	while let Ok(packet) = cap.next_packet() {
		let Some(data) = udp_payload(packet.data) else {
			continue;
		};
		packet_number += 1;

		println!("Packet #{packet_number}");
		println!("────────────────────────────────");

		let mut cursor = lib_quic::Cursor::new(&data);
		match lib_quic::LongHeader::parse(&mut cursor) {
			Ok(header) => {
				println!(" QUIC Version : {}", header.version);
				println!(" Type         : {:?}", header.packet_type);
				println!(" DCID         : {}", hex::encode(header.dcid));
				println!(" SCID         : {}", hex::encode(header.scid));
			}
			Err(err) => println!(" Not a QUIC long header: {err}"),
		}
		println!();
	}

	Ok(())
}

// endregion: --- Executors

// region:    --- Display
fn print_summary(summary: &Summary) {
	println!("Ophanim - QUIC Summary");
	println!("════════════════════════════════════");
	println!();
	println!("Connection");
	println!("  QUIC Version   {}", summary.quic.version);
	println!("  DCID           {}", summary.quic.dcid);
	println!("  SCID           {}", summary.quic.scid);
	println!();
	println!("Packets");
	println!("  Total          {}", summary.quic.packets);
	println!("  Initial        {}", summary.quic.initial_packets);
	println!("  0-RTT          {}", summary.quic.zero_rtt_packets);
	println!("  Handshake      {}", summary.quic.handshake_packets);
	println!("  Retry          {}", summary.quic.retry_packets);
	if let Some(tls) = &summary.tls {
		println!();
		println!("TLS");
		println!("  Version        {}", tls.version);
		println!("  SNI            {}", if tls.sni { "yes" } else { "no" });
		println!("  ALPN           {}", tls.alpn.as_deref().unwrap_or("-"));
		println!("  Cipher Suites  {}", tls.cipher_suites);
		println!("  Extensions     {}", tls.extensions);
	}
	if let Some(ja4) = &summary.ja4 {
		println!();
		println!("Fingerprint");
		println!("  JA4QUIC        {ja4}");
	}
	println!();
}
fn print_tls(fp: &ConnFingerprint) {
	println!("TLS ClientHello");
	println!("════════════════════════════════════");
	println!();
	println!("  Version         {}", fp.version);
	println!("  ALPN            {}", fp.alpn.as_deref().unwrap_or("-"));
	println!("  Cipher Suites   {}", fp.cipher_suites);
	println!("  Extensions      {}", fp.extensions);
	println!("  SNI             {}", if fp.sni { "yes" } else { "no" });
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
