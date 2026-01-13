use k256::{ProjectivePoint as G, Scalar as F};
use rand::rngs::OsRng;

pub fn generate_key_pair() -> (F, G) {
    let private_key = F::generate_biased(&mut OsRng);
    let public_key = G::GENERATOR * private_key;
    (private_key, public_key)
}