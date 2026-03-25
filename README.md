# Nox KMS

A Key Management Service implementing ECIES (Elliptic Curve Integrated Encryption Scheme) with RSA-wrapped shared secret delegation for the Nox Protocol.

## Description

Nox KMS provides secure cryptographic operations for key exchange within the Nox Protocol ecosystem. The service:

- Computes ECDH shared secrets using secp256k1 elliptic curve cryptography
- Encrypts the shared secret's X-coordinate using RSA-OAEP (SHA-256) for secure delegation
- Verifies request authorization via EIP-712 typed signatures
- Integrates with blockchain smart contracts to fetch the authorized gateway address
- Exposes Prometheus metrics for monitoring

### How it works

**Encryption:** Performed by the [nox-handle-gateway](https://github.com/iExec-Nox/nox-handle-gateway), which retrieves the KMS public key and encrypts data using ECIES.

**Decryption delegation:**

When an authorized party needs to decrypt, they request delegation through the gateway :

1. The KMS receives the ephemeral public key and a target RSA public key
2. It computes the same shared secret: `SharedSecret = EphemeralPubKey * KMS_PrivateKey`
3. The X-coordinate of the shared secret is encrypted with the RSA public key (RSA-OAEP SHA-256)
4. The encrypted result is returned with an EIP-712 proof signature

This allows secure delegation of decryption capabilities to the RSA key holder, without exposing the KMS private key.

## Configuration

Configuration is loaded from environment variables with the `NOX_KMS_` prefix. Nested properties use double underscore (`__`) as separator.

### Environment Variables

| Variable | Description | Default |
| -------- | ----------- | ------- |
| `NOX_KMS_SERVER__HOST` | Server bind address | `127.0.0.1` |
| `NOX_KMS_SERVER__PORT` | Server port | `9000` |
| `NOX_KMS_ECC_KEY` | EC private key (secp256k1, 32 bytes hex-encoded, 0x prefix optional) | *required* |
| `NOX_KMS_WALLET_KEY` | Wallet private key for signing proofs (32 bytes hex-encoded) | *required* |
| `NOX_KMS_CHAIN__CHAIN_ID` | Blockchain chain ID | `421614` (Arbitrum Sepolia) |
| `NOX_KMS_CHAIN__NOX_COMPUTE_CONTRACT` | NoxCompute contract address | `0x0000...0000` |
| `NOX_KMS_CHAIN__RPC_URL` | Blockchain RPC endpoint | `http://localhost:8545` |

### Secret Files

For sensitive values, you can use the `_FILE` suffix to load from a file:

```bash
NOX_KMS_ECC_KEY_FILE=/run/secrets/ecc_key
NOX_KMS_WALLET_KEY_FILE=/run/secrets/wallet_key
```

### Logging

Logging level is controlled via the `RUST_LOG` environment variable:

```bash
RUST_LOG=info    # Default
RUST_LOG=debug   # Verbose logging
```

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

## Building

```bash
cargo build --release
```

## Running

```bash
# Set required environment variables
export NOX_KMS_ECC_KEY="0x..."
export NOX_KMS_WALLET_KEY="0x..."
export NOX_KMS_CHAIN__NOX_COMPUTE_CONTRACT="0x..."
export NOX_KMS_CHAIN__RPC_URL="https://..."

# Run the service
cargo run --release
```

## License

The Nox Protocol source code is released under the Business Source License
1.1 (BUSL-1.1).

The license will automatically convert to the MIT License under the
conditions described in the LICENSE file.

The full text of the MIT License is provided in the LICENSE-MIT file.
