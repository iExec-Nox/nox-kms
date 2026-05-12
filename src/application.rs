use std::collections::HashMap;

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
const VERSIONED_PATHS: &str = "/v0/{*path}";

#[derive(Clone)]
pub struct AppState {
    pub kms_service: KmsService,
    pub metrics_handle: PrometheusHandle,
    pub gateway_addresses: HashMap<u32, Address>,
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

impl FromRef<AppState> for HashMap<u32, Address> {
    fn from_ref(state: &AppState) -> Self {
        state.gateway_addresses.clone()
    }
}

sol! {
    #[sol(rpc)]
    interface INoxCompute {
        function gateway() external view returns (address);
        function kmsPublicKey() external view returns (bytes memory);
    }
}

pub struct Application {
    config: Config,
    state: AppState,
    prometheus_layer: PrometheusMetricLayer<'static>,
}

impl Application {
    pub async fn new(config: Config) -> Result<Self> {
        let kms_service = KmsService::load_keys(&config.chains, &config.wallet_key)
            .context("Failed to load KMS keys from environment variables")?;

        let mut gateway_addresses: HashMap<u32, Address> = HashMap::new();
        for chain_id in config.chains.keys().collect::<Vec<_>>() {
            let provider = ProviderBuilder::new()
                .connect(&config.chains[chain_id].rpc_url)
                .await
                .with_context(|| {
                    format!("Failed to connect to RPC provider for chain {chain_id}")
                })?;

            let contract = INoxCompute::new(
                config.chains[chain_id].nox_compute_contract_address,
                &provider,
            );
            let gateway_address = contract.gateway().call().await.with_context(|| {
                format!(
                    "Failed to fetch gateway address from NoxCompute contract from chain {chain_id}"
                )
            })?;
            if gateway_address == Address::ZERO {
                return Err(Error::msg(format!(
                    "NoxCompute contract call to gateway() returned {} from chain {chain_id}",
                    Address::ZERO
                )));
            }

            info!(
                chain_id,
                "Gateway address {gateway_address} on chain {chain_id}"
            );
            if gateway_addresses
                .insert(*chain_id, gateway_address)
                .is_some()
            {
                return Err(Error::msg(format!(
                    "Failed to register gateway address {gateway_address} on chain {chain_id}"
                )));
            }
            let onchain_kms_pubkey = contract.kmsPublicKey().call().await.with_context(|| {
                format!("Failed to fetch kmsPublicKey() from NoxCompute on chain {chain_id}")
            })?;
            kms_service.assert_onchain_kms_pubkey_matches(&onchain_kms_pubkey, chain_id)
                .with_context(
                    || {
                        format!(
                            "Local ECC key for chain {chain_id} does not match on-chain registration at NoxCompute {}",
                            config.chains[chain_id].nox_compute_contract_address,
                        )
                    },
                )?;
            info!(chain_id, "KMS public key matches on-chain registration");
        }

        let prometheus_layer = PrometheusMetricLayerBuilder::new()
            .with_allow_patterns(&["/", "/health", "/metrics", VERSIONED_PATHS])
            .build();
        let metrics_handle = Handle::make_default_handle(Handle::default());
        Ok(Self {
            config,
            state: AppState {
                kms_service,
                metrics_handle,
                gateway_addresses,
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
