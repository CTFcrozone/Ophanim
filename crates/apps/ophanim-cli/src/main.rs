// region:    --- Modules

mod cli;
mod error;

pub use error::{Error, Result};
use tracing_subscriber::EnvFilter;

// endregion: --- Modules

#[tokio::main]
async fn main() -> Result<()> {
	tracing_subscriber::fmt()
		.with_target(false)
		.without_time()
		.with_env_filter(EnvFilter::from_default_env())
		.init();

	cli::execute().await?;

	Ok(())
}
