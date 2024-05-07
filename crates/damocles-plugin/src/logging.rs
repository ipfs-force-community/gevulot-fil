//! provides logging helpers

use time::format_description::well_known;
use time::util::local_offset;
use time::UtcOffset;
use tracing_subscriber::filter::{self};
use tracing_subscriber::fmt::layer;
use tracing_subscriber::fmt::time::OffsetTime;
use tracing_subscriber::prelude::*;
use tracing_subscriber::registry;

/// initiate the global tracing subscriber
pub fn init() {
    let env_filter = filter::EnvFilter::builder()
        .with_default_directive(filter::LevelFilter::INFO.into())
        .from_env_lossy();

    unsafe {
        // SAFETY: It's sound as we don't manipulate environment variables while querying local offsets.
        local_offset::set_soundness(local_offset::Soundness::Unsound);
    }
    let timer = OffsetTime::new(
        UtcOffset::current_local_offset().unwrap_or(UtcOffset::UTC),
        well_known::Rfc3339,
    );

    let fmt_layer = layer()
        .with_writer(std::io::stderr)
        .with_target(true)
        .with_thread_ids(true)
        .with_timer(timer)
        .with_filter(env_filter);

    registry().with(fmt_layer).init();
}
