//! This crate contains implementations of hash functions.

mod md4;
mod sha1;
mod util;

pub use md4::Md4;
pub use sha1::Sha1;
