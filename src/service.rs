use k256::{ProjectivePoint as G, Scalar as F};
use crate::elliptic::generate_key_pair;

#[derive(Clone)]
pub struct KmsService {
    pub private_key: F,
    pub public_key: G,
}

impl KmsService {
    pub fn initialize() -> Self {
        let (private_key, public_key) = generate_key_pair();
        Self {
            private_key,
            public_key,
           
        }
    }
}