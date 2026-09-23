use std::path::PathBuf;

use clap::{Parser, Subcommand};

#[derive(Parser, Debug)]
#[command(version, about = "Ophanim - QUIC analysis toolkit")]
pub struct CliCmd {
	/// QUIC packet capture or input file
	#[arg(short, long)]
	pub path: PathBuf,

	#[command(subcommand)]
	pub command: Mode,
}

#[derive(Subcommand, Debug)]
pub enum Mode {
	/// Show a compact QUIC/TLS summary
	Summary,

	/// Show TLS ClientHello information
	Tls,

	/// Show JA4QUIC fingerprint
	Ja4,

	/// Show detailed packet, frame, TLS and QUIC information
	Verbose,
}
