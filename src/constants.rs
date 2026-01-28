use k256::ProjectivePoint;

pub const KEY_FILE_SIZE: usize = 65;
pub const G: ProjectivePoint = ProjectivePoint::GENERATOR;
pub const MIN_RSA_KEY_HEX_LEN: usize = 512; // 256 bytes (RSA-2048 modulus) = 512 hex chars
pub const EXPECTED_EPHEMERAL_PUB_KEY_HEX_LEN: usize = 66; // 33 bytes = 66 hex chars
// EIP-712 domain name for PublicKeyProof generation
pub const PROTOCOL_PUBLIC_KEY_EIP712_DOMAIN_NAME: &str = "ProtocolPublicKey";
