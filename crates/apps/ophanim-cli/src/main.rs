// region:    --- Modules

mod cli;
mod error;

pub use error::{Error, Result};

// endregion: --- Modules

#[tokio::main]
async fn main() -> Result<()> {
	cli::execute()?;

	Ok(())
}
