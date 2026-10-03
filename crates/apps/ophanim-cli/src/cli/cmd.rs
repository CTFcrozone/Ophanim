use std::path::{Path, PathBuf};

use clap::{Parser, Subcommand};

use crate::{Error, Result};

#[derive(Parser, Debug)]
#[command(version, about = "Ophanim - QUIC analysis toolkit")]
pub struct CliCmd {
	/// QUIC packet capture or input file
	#[arg(short, long, global = true)]
	pub path: Option<PathBuf>,

	#[command(subcommand)]
	pub command: Mode,
}

impl CliCmd {
	/// Path for the file-based modes.
	pub fn path(&self) -> Result<&Path> {
		self.path
			.as_deref()
			.ok_or_else(|| Error::custom("--path is required for this command"))
	}
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

	/// Capture live packets from the default device and print QUIC headers
	Live,
}
