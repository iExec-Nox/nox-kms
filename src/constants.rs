use k256::ProjectivePoint;

pub const KEY_FILE_SIZE: usize = 65;
pub const G: ProjectivePoint = ProjectivePoint::GENERATOR;
pub const MIN_RSA_KEY_HEX_LEN: usize = 2 * 256; // 2*256 bytes = 2048 bits = 512 hex chars
pub const EXPECTED_EPHEMERAL_PUB_KEY_HEX_LEN: usize = 66; // 33 bytes = 66 hex chars
