use alloy_primitives::Address;
use alloy_provider::ProviderBuilder;
use alloy_sol_types::sol;
use anyhow::{Context, Error, Result};
use axum::{
    Router,
    extract::FromRef,
    routing::{get, post},
};
use axum_prometheus::{
    Handle, MakeDefaultHandle, PrometheusMetricLayer, PrometheusMetricLayerBuilder,
};
use metrics_exporter_prometheus::PrometheusHandle;
use tokio::signal;
use tower_http::trace::TraceLayer;
use tracing::{debug, info, warn};

use crate::config::Config;
use crate::handlers;
use crate::service::KmsService;

const ENDPOINT_VERSION: &str = "/v0";
const VERSIONED_PATHS: &str = "/v0/*path";

#[derive(Clone)]
pub struct AppState {
    pub kms_service: KmsService,
    pub metrics_handle: PrometheusHandle,
    pub gateway_address: Address,
}

impl FromRef<AppState> for KmsService {
    fn from_ref(state: &AppState) -> Self {
        state.kms_service.clone()
    }
}

impl FromRef<AppState> for PrometheusHandle {
    fn from_ref(state: &AppState) -> Self {
        state.metrics_handle.clone()
    }
}

impl FromRef<AppState> for Address {
    fn from_ref(state: &AppState) -> Self {
        state.gateway_address
    }
}

sol! {
    #[sol(rpc)]
    interface INoxCompute {
        function gateway() external view returns (address);
    }
}

pub struct Application {
    config: Config,
    state: AppState,
    prometheus_layer: PrometheusMetricLayer<'static>,
}

impl Application {
    pub async fn new(config: Config) -> Result<Self> {
        let kms_service =
            KmsService::load_keys(config.chain.chain_id, &config.ecc_key, &config.wallet_key)
                .context("Failed to load KMS keys from environment variables")?;

        let provider = ProviderBuilder::new()
            .connect(&config.chain.rpc_url)
            .await
            .context("Failed to connect to RPC provider")?;

        let contract = INoxCompute::new(config.chain.nox_compute_contract, &provider);
        let gateway_address = contract
            .gateway()
            .call()
            .await
            .context("Failed to fetch gateway address from NoxCompute contract")?;
        if gateway_address == Address::ZERO {
            return Err(Error::msg(format!(
                "NoxCompute contract call to gateway() returned {}",
                Address::ZERO
            )));
        }

        info!("Gateway address: {gateway_address}");

        let prometheus_layer = PrometheusMetricLayerBuilder::new()
            .with_allow_patterns(&["/", "/health", "/metrics", VERSIONED_PATHS])
            .build();
        let metrics_handle = Handle::make_default_handle(Handle::default());
        Ok(Self {
            config,
            state: AppState {
                kms_service,
                metrics_handle,
                gateway_address,
            },
            prometheus_layer,
        })
    }

    fn build_router(&self) -> Router {
        debug!("Building application router");

        let versioned_route = Router::new().route("/delegate", post(handlers::delegate));

        Router::new()
            // Root endpoint
            .route("/", get(handlers::root))
            // Health check endpoint
            .route("/health", get(handlers::health_check))
            // Metrics endpoint
            .route("/metrics", get(handlers::metrics))
            // Functionality endpoints
            .nest(ENDPOINT_VERSION, versioned_route)
            // Fallback handler for non-existing routes
            .fallback(handlers::not_found)
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
