use k256::{
    ProjectivePoint as G, Scalar as F,
    elliptic_curve::{Field, rand_core::OsRng},
};

pub fn generate_key_pair() -> (F, G) {
    let private_key = F::random(&mut OsRng);
    let public_key = G::GENERATOR * private_key;
    (private_key, public_key)
}
