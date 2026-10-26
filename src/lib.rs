#![deny(unsafe_code)]

pub mod auth;
pub mod config;
pub mod engine;
pub mod error;
pub mod ip;
pub mod net;
pub mod provider;
pub mod server;

pub fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}
