use derive_more::{Display, From};

pub type Result<T> = core::result::Result<T, Error>;

#[derive(Debug, Display, From)]
pub enum Error {
	#[display("Error: {_0}")]
	#[from(String, &String, &str)]
	Custom(String),

	#[display("Invalid command-line arguments: {_0}")]
	#[from]
	Clap(clap::Error),

	#[display("Failed to parse QUIC packet: {_0}")]
	#[from]
	Quic(lib_quic::Error),

	#[display("Failed to read packet capture: {_0}")]
	#[from]
	Pcap(pcap::Error),

	#[display("I/O error: {_0}")]
	#[from]
	Io(std::io::Error),
}

// region:    --- Custom

impl Error {
	pub fn custom_from_err(err: impl std::error::Error) -> Self {
		Self::Custom(err.to_string())
	}

	pub fn custom(val: impl Into<String>) -> Self {
		Self::Custom(val.into())
	}
}

// endregion: --- Custom

// region:    --- Error Boilerplate

impl std::error::Error for Error {}

// endregion: --- Error Boilerplate
