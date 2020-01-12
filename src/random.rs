//! Random Number generation for the Mesh.
//! Generalized over the rand Library so there's no hard dependencies.

use rand::distributions::{Distribution, Standard};

pub trait Randomizable: Sized {
    /// Generates and returns a random `T`. Currently essentially just an alias for `rand::random`
    /// Assume `random` to be not secure! Even though `random` could use a cryptographically secure
    /// random number generator behind the scenes, use `random_secure` if you need crypto-random.
    fn random() -> Self {
        Self::random_secure()
    }
    /// Generates and returns a cryptographically secure random `T`.
    fn random_secure() -> Self;
}
impl<T> Randomizable for T
where
    Standard: Distribution<T>,
{
    fn random_secure() -> Self {
        rand::random()
    }
}
