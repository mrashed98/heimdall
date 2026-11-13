//! Logs and traces. Logs are JSON lines on stdout, filtered by `RUST_LOG`
//! (default `info`). When `OTEL_EXPORTER_OTLP_ENDPOINT` is set, spans are
//! also exported over OTLP/HTTP; the exporter reads that variable (and the
//! other standard `OTEL_*` ones) itself.

use anyhow::Context;
use opentelemetry::trace::TracerProvider;
use opentelemetry_sdk::trace::SdkTracerProvider;
use opentelemetry_sdk::Resource;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::EnvFilter;

/// Keep this alive for the life of the process: dropping it flushes the
/// spans still buffered and stops the exporter.
pub struct Guard {
    provider: Option<SdkTracerProvider>,
}

impl Drop for Guard {
    fn drop(&mut self) {
        if let Some(p) = self.provider.take() {
            if let Err(e) = p.shutdown() {
                eprintln!("telemetry: flushing spans failed: {e}");
            }
        }
    }
}

/// Install the global tracing subscriber. Call once, before anything logs.
pub fn init(service_name: &str) -> anyhow::Result<Guard> {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    let json = tracing_subscriber::fmt::layer()
        .json()
        .with_current_span(true)
        .with_target(true);

    let otlp_set = std::env::var("OTEL_EXPORTER_OTLP_ENDPOINT").is_ok_and(|v| !v.is_empty());
    let provider = if otlp_set {
        let exporter = opentelemetry_otlp::SpanExporter::builder()
            .with_http()
            .build()
            .context("building the OTLP span exporter")?;
        Some(
            SdkTracerProvider::builder()
                .with_batch_exporter(exporter)
                .with_resource(
                    Resource::builder()
                        .with_service_name(service_name.to_string())
                        .build(),
                )
                .build(),
        )
    } else {
        None
    };
    // `Option<Layer>` is itself a layer that does nothing when None.
    let otel = provider
        .as_ref()
        .map(|p| tracing_opentelemetry::layer().with_tracer(p.tracer(service_name.to_string())));

    tracing_subscriber::registry()
        .with(filter)
        .with(json)
        .with(otel)
        .try_init()
        .context("installing the tracing subscriber")?;
    if otlp_set {
        tracing::info!("exporting traces over OTLP");
    }
    Ok(Guard { provider })
}
