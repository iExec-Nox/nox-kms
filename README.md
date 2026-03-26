# Nox KMS

[![License](https://img.shields.io/badge/license-BUSL--1.1-blue)](./LICENSE) [![Docs](https://img.shields.io/badge/docs-nox--protocol-purple)](https://docs.iex.ec) [![Discord](https://img.shields.io/badge/chat-Discord-5865F2)](https://discord.com/invite/5TewNUnJHN) [![Ship](https://img.shields.io/github/v/tag/iExec-Nox/nox-kms?label=ship)](https://github.com/iExec-Nox/nox-kms/releases)

> Key Management Service for ECIES delegation in the Nox Protocol.

## Table of Contents

- [Nox KMS](#nox-kms)
  - [Table of Contents](#table-of-contents)
  - [Overview](#overview)
  - [Prerequisites](#prerequisites)
  - [Getting Started](#getting-started)
  - [Environment Variables](#environment-variables)
  - [API Reference](#api-reference)
    - [Service Endpoints](#service-endpoints)
      - [`GET /`](#get-)
      - [`GET /health`](#get-health)
      - [`GET /metrics`](#get-metrics)
    - [Cryptographic Endpoints](#cryptographic-endpoints)
      - [`POST /v0/delegate`](#post-v0delegate)
  - [Related Repositories](#related-repositories)
  - [License](#license)

---

## Overview

The KMS is the cryptographic core of the Nox Protocol. It holds the EC private key used to derive ECDH shared secrets and never exposes it. All encryption happens in the [nox-handle-gateway](https://github.com/iExec-Nox/nox-handle-gateway); the KMS only performs delegation for authorized decryption requests.

**Delegation (`POST /v0/delegate`):** When an authorized party needs to decrypt a value, the [nox-handle-gateway](https://github.com/iExec-Nox/nox-handle-gateway) forwards an ephemeral public key and the caller's RSA public key to this KMS. The KMS computes the ECDH shared secret (`SharedSecret = EphemeralPubKey * KMS_PrivateKey`), encrypts its X-coordinate with the RSA key (RSA-OAEP SHA-256), and returns the result with an EIP-712 proof signature. The caller decrypts locally; the KMS private key never leaves this service.

---

## Prerequisites

- Rust >= 1.85 (edition 2024)
- Access to an Ethereum RPC endpoint
- A running [nox-handle-gateway](https://github.com/iExec-Nox/nox-handle-gateway) instance to call this KMS

---

## Getting Started

```bash
git clone https://github.com/iExec-Nox/nox-kms.git
cd nox-kms

# Set required environment variables
export NOX_KMS_ECC_KEY="0x..."
export NOX_KMS_WALLET_KEY="0x..."
export NOX_KMS_CHAIN__RPC_URL="https://..."
export NOX_KMS_CHAIN__NOX_COMPUTE_CONTRACT="0x..."

# Build and run
cargo run --release
```

---

## Environment Variables

Configuration is loaded from environment variables with the `NOX_KMS_` prefix. Nested properties use double underscore (`__`) as separator.

| Variable | Description | Required | Default |
| -------- | ----------- | -------- | ------- |
| `NOX_KMS_SERVER__HOST` | Server bind address | No | `127.0.0.1` |
| `NOX_KMS_SERVER__PORT` | Server port | No | `9000` |
| `NOX_KMS_ECC_KEY` | EC private key (secp256k1, 32 bytes hex-encoded, 0x prefix optional) | **Yes** | — |
| `NOX_KMS_WALLET_KEY` | Wallet private key for signing proofs (32 bytes hex-encoded) | **Yes** | — |
| `NOX_KMS_CHAIN__CHAIN_ID` | Blockchain chain ID | No | `421614` (Arbitrum Sepolia) |
| `NOX_KMS_CHAIN__NOX_COMPUTE_CONTRACT` | NoxCompute contract address | No | `0x0000...0000` |
| `NOX_KMS_CHAIN__RPC_URL` | Blockchain RPC endpoint | **Yes** | `http://localhost:8545` |

For sensitive values, you can use the `_FILE` suffix to load from a file:

```bash
NOX_KMS_ECC_KEY_FILE=/run/secrets/ecc_key
NOX_KMS_WALLET_KEY_FILE=/run/secrets/wallet_key
```

Logging level is controlled via the `RUST_LOG` environment variable:

```bash
RUST_LOG=info    # Default
RUST_LOG=debug   # Verbose logging
```

---

## API Reference

### Service Endpoints

#### `GET /`

Returns basic service information.

**Response:**

```json
{
  "service": "nox-kms",
  "timestamp": "2024-01-15T10:30:00.000Z"
}
```

#### `GET /health`

Health check endpoint for monitoring and orchestration.

**Response:**

```json
{
  "status": "ok"
}
```

#### `GET /metrics`

Prometheus metrics endpoint for observability.

**Response:** Prometheus text format metrics.

---

### Cryptographic Endpoints

#### `POST /v0/delegate`

Computes and RSA-encrypts an ECDH shared secret for ECIES delegation.

**Headers:**

| Header | Description |
| ------ | ----------- |
| `Authorization` | `Bearer 0x<eip712_signature>` - EIP-712 signature from the authorized gateway |

**Request Body:**

```json
{
  "ephemeralPubKey": "0x02...",
  "targetPubKey": "0x3082..."
}
```

| Field | Description |
| ----- | ----------- |
| `ephemeralPubKey` | Compressed SEC1 EC public key (33 bytes = 66 hex chars + `0x` prefix). Format: `0x02...` or `0x03...` |
| `targetPubKey` | RSA public key in SPKI DER format (minimum 2048 bits), hex-encoded with `0x` prefix |

**Success Response (200):**

```json
{
  "encryptedSharedSecret": "0x...",
  "proof": "0x..."
}
```

| Field | Description |
| ----- | ----------- |
| `encryptedSharedSecret` | RSA-OAEP encrypted X-coordinate of the shared secret (256 bytes for RSA-2048, 512 bytes for RSA-4096), hex-encoded |
| `proof` | EIP-712 signature of the response by the KMS wallet |

**Error Responses:**

| Status | Description |
| ------ | ----------- |
| `400 Bad Request` | Invalid key format, size, or encoding |
| `401 Unauthorized` | Missing or invalid authorization signature |

**EIP-712 Domain (for authorization signature):**

```text
name: "ProtocolDelegate"
version: "1"
chainId: <configured_chain_id>
```

**EIP-712 Message Type:**

```solidity
struct DelegateAuthorization {
    string ephemeralPubKey;
    string targetPubKey;
}
```

---

## Related Repositories

| Repository | Role |
| ---------- | ---- |
| [nox-handle-gateway](https://github.com/iExec-Nox/nox-handle-gateway) | Handle Gateway — encrypts values, manages ciphertext storage, calls this KMS for delegation |

---

## License

The Nox Protocol source code is released under the Business Source License 1.1 (BUSL-1.1).

The license will automatically convert to the MIT License under the conditions described in the [LICENSE](./LICENSE) file.

The full text of the MIT License is provided in the [LICENSE-MIT](./LICENSE-MIT) file.
