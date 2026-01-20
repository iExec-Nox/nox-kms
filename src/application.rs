use anyhow::{Context, Result};
use axum::{
    Router,
    routing::{get, post},
};
use axum_prometheus::PrometheusMetricLayer;
use metrics_exporter_prometheus::PrometheusHandle;
use tokio::signal;
use tower_http::trace::TraceLayer;
use tracing::{debug, info, warn};

use crate::config::Config;
use crate::handlers;
use crate::service::KmsService;

#[derive(Clone)]
pub struct AppState {
    pub kms_service: KmsService,
    pub metrics_handle: PrometheusHandle,
}

pub struct Application {
    config: Config,
    state: AppState,
    prometheus_layer: PrometheusMetricLayer<'static>,
}

impl Application {
    pub fn new(config: Config) -> Result<Self> {
        let kms_service = KmsService::load_or_generate(&config.key_file)
            .context("Failed to load or generate KMS keys")?;
        let (prometheus_layer, metrics_handle) = PrometheusMetricLayer::pair();
        Ok(Self {
            config,
            state: AppState {
                kms_service,
                metrics_handle,
            },
            prometheus_layer,
        })
    }

    fn build_router(&self) -> Router {
        debug!("Building application router");
        let v0_routes = Router::new()
            .route("/public-key", get(handlers::get_public_key))
            .route("/delegate", post(handlers::delegate));

        Router::new()
            // Root endpoint
            .route("/", get(handlers::root))
            // Health check endpoint
            .route("/health", get(handlers::health_check))
            .route("/metrics", get(handlers::metrics))
            .nest("/v0", v0_routes)
            .with_state(self.state.clone())
            .layer(TraceLayer::new_for_http())
            .layer(self.prometheus_layer.clone())
    }

    pub async fn run(self) -> Result<()> {
        let addr = self.config.bind_addr();
        let app = self.build_router();
        let listener = tokio::net::TcpListener::bind(&addr)
            .await
            .with_context(|| format!("Failed to bind server to address {}", addr))?;

        info!("Server bound to {}", addr);

        axum::serve(listener, app)
            .with_graceful_shutdown(shutdown_signal())
            .await
            .context("Server encountered an error during execution")?;

        info!("Server shutdown complete");
        Ok(())
    }
}

async fn shutdown_signal() {
    let ctrl_c = async {
        signal::ctrl_c()
            .await
            .expect("failed to install Ctrl+C handler");
    };

    #[cfg(unix)]
    let terminate = async {
        signal::unix::signal(signal::unix::SignalKind::terminate())
            .expect("failed to install signal handler")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {
            info!("Received Ctrl+C, shutting down gracefully...");
        },
        _ = terminate => {
            info!("Received SIGTERM, shutting down gracefully...");
        },
    }

    warn!("Shutdown signal received, cleaning up...");
}
