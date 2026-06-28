//! Error type shared on the request path. House rule (BUDU-DEV.md): never
//! `unwrap`/`expect` on the request path — bubble these with `?` instead.

use thiserror::Error;

#[derive(Debug, Error)]
pub enum BuduError {
    #[error("config error: {0}")]
    Config(String),

    #[error("invalid request: {0}")]
    BadRequest(String),

    #[error("upstream error: {0}")]
    Upstream(String),

    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
}
