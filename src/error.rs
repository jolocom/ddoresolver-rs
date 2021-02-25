use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    #[error("did_key error: {0}")]
    DidKeyError(String),
}
